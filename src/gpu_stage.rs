//| The [`MutationalStage`] is the default stage used during fuzzing.
//! For the current input, it will perform a range of random mutations, and then run them in the executor.

use std::{fmt::Debug, borrow::BorrowMut};
use std::thread;

use core::marker::PhantomData;

#[cfg(feature = "introspection")]
use crate::monitors::PerfFeature;
use libafl::{
    bolts::current_time,
    bolts::rands::Rand,
    corpus::Corpus,
    fuzzer::Evaluator,
    inputs::Input,
    mark_feature_time,
    mutators::Mutator,
    stages::Stage,
    start_timer,
    state::{HasClientPerfMonitor, HasCorpus, HasRand, HasExecutions, HasMetadata, HasSolutions, HasStartTime,},
    Error, ExecuteInputResult
};

use std::rc::Rc;
use std::cell::RefCell;
use std::time::Instant;

use serde::Serialize;
use serde_traitobject::Any;
use std::ptr;
use core::{
    cmp::{max, min},
};
use std::process::exit;
use crate::evm::config::{NJOBS, SEED_SIZE, RUN_FOREVER, GPU_ENABLE, STATS_CPU_DEFAULT, GPU_BALANCE_PERCENT};
use crate::evm::vm::EVMState;
use crate::state::{HasCaller, HasExecutionResult};
use crate::evm::input::EVMInput;
use crate::{
    input::VMInputT,
    state::{HasCurrentInputIdx, HasInfantStateState, HasItyState, InfantStateState},
    state_input::StagedVMState, evm::{types::EVMAddress, input::EVMInputT, abi::BoxedABI},
};
use crate::evm::types::EVMU256;
use bytes::Bytes;

use crate::generic_vm::vm_state::VMStateT;
use serde::de::DeserializeOwned;

use crate::tracer::build_basic_txn;
use crate::fuzzer::ExecuteCudaInputResult;
use crate::evm::host::{CMP_MAP, BRANCH_DISTANCE, BRANCH_DISTANCE_INTERESTING, BRANCH_DISTANCE_CHANGED};
use crate::generic_vm::vm_executor::{MAP_SIZE};

#[link(name = "runner")]
extern "C" {
    fn cuLoadSeed(caller_ptr: *const u8, value_ptr: *const u8, data_ptr: *const u8, data_size: u32, thread: u32);
    fn cuEvalTxn(nwrap: u32);
    fn getCudaExecRes(pcov: *const u64, pbug: *const u64) -> bool;
    fn isCudaInteresting(tid: u32) -> u8;
    fn cuDumpStorage(threadId: u32);
    fn cuLoadStorage(src: *const u8, slotCnt: u32, wrapi: u32);
}



/// A Mutational stage is the stage in a fuzzing run that mutates inputs.
/// Mutational stages will usually have a range of mutations that are
/// being applied to the input one by one, between executions.
pub trait MutationalStage<E, EM, I, M, S, Z>: Stage<E, EM, S, Z>
where
    M: Mutator<I, S>,
    I: Input + Serialize + EVMInputT + VMInputT<EVMState, EVMAddress, EVMAddress>+ 'static,
    S: HasClientPerfMonitor + HasCorpus<I> + HasExecutions + HasRand,
    Z: Evaluator<E, EM, I, S>,
{
    /// The mutator registered for this stage
    fn mutator(&self) -> &M;

    /// The mutator registered for this stage (mutable)
    fn mutator_mut(&mut self) -> &mut M;

    /// Gets the number of iterations this mutator should run for.
    fn iterations(&self, state: &mut S, corpus_idx: usize) -> Result<usize, Error>;

    /// Runs this (mutational) stage for the given testcase
    #[allow(clippy::cast_possible_wrap)] // more than i32 stages on 32 bit system - highly unlikely...
    fn perform_mutational(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error> {
        let num = self.iterations(state, corpus_idx)?;

        for i in 0..num {
            start_timer!(state);
            let mut input = state
                .corpus()
                .get(corpus_idx)?
                .borrow_mut()
                .load_input()?
                .clone();
            mark_feature_time!(state, PerfFeature::GetInputFromCorpus);

            start_timer!(state);
            self.mutator_mut().mutate(state, &mut input, i as i32)?;
            mark_feature_time!(state, PerfFeature::Mutate);

            // Time is measured directly the `evaluate_input` function
            let (_, corpus_idx) = fuzzer.evaluate_input(state, executor, manager, input)?;

            start_timer!(state);
            self.mutator_mut().post_exec(state, i as i32, corpus_idx)?;
            mark_feature_time!(state, PerfFeature::MutatePostExec);
        }
        Ok(())
    }

    /// Runs this (mutational) stage in GPU for the given testcase
    #[allow(clippy::cast_possible_wrap)] // more than i32 stages on 32 bit system - highly unlikely...
    fn perform_one_mutational(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error> {
        let corpus_size = NJOBS as usize;//state.corpus().count();
        let wrap_count = min(corpus_size, NJOBS as usize);
        let slot_count = NJOBS as usize / wrap_count;

        let mut input = state
            .corpus()
            .get(corpus_idx)?
            .borrow_mut()
            .load_input()?
            .clone();

        // set the environmental parameters
        input.cu_load_evm_env();

        // load the storage
        if let Some(storage) = input.as_any().downcast_ref::<EVMInput>().unwrap().get_state().get(&input.get_evm_addr()) {
            let mut bytes = Vec::new();
            // println!("storage content before executing input=>");
            for (key, value) in storage {
                // for (key, value) in storage {
                //     println!("{:#x}: {:#x}", key, value);
                // }
                let slot = [key.as_le_bytes(), value.as_le_bytes()].concat();
                bytes.extend(slot);
            }
            unsafe{ cuLoadStorage(bytes.as_ptr(), storage.len() as u32, 0 as u32); }
        } else {
            // println!("Empty storage"); 
            unsafe{ cuLoadStorage(ptr::null(), 0, 0 as u32); }
        }

        let mut tid:u32 = 0;
        let mut input_vec: Vec<I> = Vec::new();
        let num = NJOBS as usize;// slot_count;
        for i in 0..num {
            // mutate the arguments and transactions (in state)
            self.mutator_mut().mutate(state, &mut input, i as i32)?;
            input_vec.push(input.clone());
            input.cu_load_input(tid);
            tid += 1;
        }
        // run
        unsafe {
            cuEvalTxn(wrap_count as u32);
        }
        *state.executions_mut() += tid as usize; 
        unsafe {
            let mut _cov : u64 = 0; // remove
            let mut _buggy : u64 = 0; // remove
            let _ = getCudaExecRes(&_cov, &_buggy);
        }
        for (thread_id, thread_input) in input_vec.iter().enumerate() {
            // let thread_input = tmp_in.as_any_mut().downcast_ref::<I>().unwrap().clone();
            let hnb : ExecuteCudaInputResult = unsafe { 
                let r = isCudaInteresting(thread_id as u32);
                // println!("hnb[{:?}] = {:?}", thread_id, r);
                std::mem::transmute(r)
            };
            match hnb {
                ExecuteCudaInputResult::EXECNONE => {
                    // println!("============= EXEC NONE Seed =============");
                    let _ = fuzzer.evaluate_input(state, executor, manager, thread_input.clone())?;
                    continue;
                }
                ExecuteCudaInputResult::EXECREVERTED => {
                    continue;
                }
                ExecuteCudaInputResult::EXECBUGGY => {
                    // unsafe{ cuDumpStorage(thread_id as u32); }
                    #[cfg(feature = "print_txn_corpus")]
                    {       
                        // println!("[bug] bug() hit at {:?}\n\t{:?}\n=>{:?}\n", thread_id, thread_input, thread_input.get_calldata());
                        let _ = fuzzer.evaluate_input(state, executor, manager, thread_input.clone())?;
                    }
                    if !unsafe { RUN_FOREVER } {
                        exit(0);
                    }
                }
                ExecuteCudaInputResult::EXECINTERESTING => {
                    let _ = fuzzer.evaluate_input(state, executor, manager, thread_input.clone())?;
                }
                _ => {
                    unreachable!();
                }
            }
        }
        Ok(())
    }


    /// Runs this (mutational) stage in GPU for all testcase
    #[allow(clippy::cast_possible_wrap)] // more than i32 stages on 32 bit system - highly unlikely...
    fn perform_multiple_mutational(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error> {
        #[link(name = "runner")]
        extern "C" {
            fn cuPreMutate(argTypes: *const u8, argTypesLen: u32);
            fn cuMutate(calldasize: u32);
            fn cuEvalTxn(nwrap: u32);
            fn getCudaExecRes(pcov: *const u64, pbug: *const u64) -> bool;
            fn isCudaInteresting(tid: u32) -> u8;
            fn gainCov(tid: u32, RawSeed: *mut u8) -> u8;
        }
        
        let mut tx_bytes:[u8; SEED_SIZE] = [0; SEED_SIZE];
        for i in 0..self.iterations(state, corpus_idx)? {

            #[cfg(any(test, feature = "debug"))]
            let first_start_time = Instant::now();
            let start_time = Instant::now();

            // default run in CPU environment;
            let mut cpu_input = state
                .corpus()
                .get(corpus_idx)?
                .borrow_mut()
                .load_input()?
                .clone();
            self.mutator_mut().mutate(state, &mut cpu_input, i as i32)?;
            let cpu_calldata = cpu_input.to_bytes();
            let cpu_calldatasize = cpu_calldata.len();

            let (_, new_corpus_idx) = fuzzer.evaluate_input(state, executor, manager, cpu_input.clone())?;
            self.mutator_mut().post_exec(state, i as i32, new_corpus_idx)?;

            if cpu_input.as_any().downcast_ref::<EVMInput>().unwrap().is_step()
               || cpu_calldatasize <= 4 {
                continue;
            }
            if unsafe { !BRANCH_DISTANCE_INTERESTING } {
                if state.rand_mut().below(100) < GPU_BALANCE_PERCENT {
                    continue;
                }
            }
            #[cfg(any(test, feature = "debug"))] 
            println!("[-] time cost on CPU execution {:?} us", start_time.elapsed().as_micros()); 
            let start_time = Instant::now();

            // if cpu_calldatasize >= 4 {
            //     println!("method => {:#x}{:#x}{:#x}{:#x}", cpu_calldata[0], cpu_calldata[1], cpu_calldata[2], cpu_calldata[3]); 
            // }
            // println!("GPU boosting input4 = {:?}", cpu_input.get_calldata());
            // if cpu_input.get_calldata()[0] == 0 && cpu_input.get_calldata()[1] == 0 {
            //     exit(0);
            // }
            // println!("GPU boosting #{:?}", corpus_idx);
            
            // Fuzz one batch of inputs in GPU
            
            // setup environmental parameters
            cpu_input.cu_load_evm_env();
            #[cfg(any(test, feature = "debug"))]
            println!("[-] time cost on env loading {:?} us", start_time.elapsed().as_micros()); 
            let start_time = Instant::now();

            // setup storage state
            if let Some(storage) = cpu_input.as_any().downcast_ref::<EVMInput>().unwrap().get_state().get(&cpu_input.get_evm_addr()) {
                let mut bytes = Vec::new();
                // println!("CPU: storage content before executing input=> {:?} slots", storage.len());
                for (key, value) in storage {
                    // println!("{:#x}: {:#x}", key, value);
                    let slot = [key.as_le_bytes(), value.as_le_bytes()].concat();
                    bytes.extend(slot);
                }
                unsafe{ cuLoadStorage(bytes.as_ptr(), storage.len() as u32, 0 as u32); }
            } else {
                unsafe{ cuLoadStorage(ptr::null(), 0, 0 as u32); }
            }

            #[cfg(any(test, feature = "debug"))] 
            println!("[-] time cost on state loading {:?} us", start_time.elapsed().as_micros()); 
            let start_time = Instant::now();

            #[cfg(any(test, feature = "debug"))]
            let mut input_vector : Vec<I> = Vec::new();
            
            // one-by-by mutation
            // for tid in 0..NJOBS {
            //     let mut case_input = cpu_input.clone();
            //     // mutate transaction arguments only
            //     case_input.set_cuda_input(true);
            //     self.mutator_mut().mutate(state, &mut case_input, -1)?;
            //     case_input.set_cuda_input(false);
            //     #[cfg(any(test, feature = "debug"))] {
            //         input_vector.push(case_input.clone());
            //     }
            //     case_input.cu_load_input(tid);
            // }
            
            // GPU mutation
            let input_type_vec = cpu_input
                .as_any()
                .downcast_ref::<EVMInput>()
                .unwrap()
                .get_types_vec();
            {
                // let data = cpu_input.to_bytes();
                // println!("method => {:#x}{:#x}{:#x}{:#x}", data[0], data[1], data[2], data[3]); 
                // println!("input_type_vec = {:?}", input_type_vec);
            }
            cpu_input.cu_load_input(0);
            unsafe {
                cuPreMutate(input_type_vec.as_ptr(), input_type_vec.len() as u32);
            }

            let should_havoc = state.rand_mut().below(100) < 60;
            let havoc_times = if should_havoc {
                state.rand_mut().below(10) + 1
            } else {
                1
            };
            for _ in 0..havoc_times {
                unsafe {
                    cuMutate(cpu_calldatasize as u32);
                }
            }
            #[cfg(any(test, feature = "debug"))]
            println!("[-] time cost on data copy {:?} us", start_time.elapsed().as_micros()); 
            let start_time = Instant::now();

            // run in GPU
            unsafe {
                cuEvalTxn(0);
            }
            *state.executions_mut() += NJOBS as usize; 
            println!("[-] GPU execution throughput {:?} execs/s", NJOBS as u128 * 1000000 / start_time.elapsed().as_micros()); 

            #[cfg(any(test, feature = "debug"))]
            println!("[-] time cost on SIMD execution {:?} us", start_time.elapsed().as_micros()); 
            let start_time = Instant::now();

            unsafe {
                let mut _cov : u64 = 0; // remove
                let mut _buggy : u64 = 0; // remove
                let _ = getCudaExecRes(&_cov, &_buggy);
            }
            for thread_id in 0..NJOBS {
                let hnb : ExecuteCudaInputResult = unsafe { 
                    let r = gainCov(thread_id as u32, tx_bytes.as_mut_ptr());
                    // let r = isCudaInteresting(thread_id as u32);
                    // println!("hnb[{:?}] = {:?}", thread_id, r);
                    std::mem::transmute(r)
                };
                match hnb {
                    ExecuteCudaInputResult::EXECNONE => {
                        continue;
                    }
                    ExecuteCudaInputResult::EXECREVERTED => {
                        continue;
                    }
                    ExecuteCudaInputResult::EXECBUGGY => {
                        let mut thread_input = cpu_input.clone();

                        // println!("current CPU caller=> {:?}", thread_input.get_caller());
                        let new_caller = &mut tx_bytes[..20];
                        new_caller.reverse();
                        // println!("going to be caller=> {:?}", hex::encode(&new_caller));
                        thread_input.set_caller(EVMAddress::from_slice(&new_caller));
                        // println!("now CPU caller=> {:?}", thread_input.get_caller());

                        thread_input.set_txn_value(EVMU256::try_from_be_slice(&tx_bytes[32..64]).unwrap());
                        // println!("current CPU data=> \ntypes:{:?}\ndata:{:?}", thread_input.get_types_vec(), hex::encode(thread_input.to_bytes()));
                        thread_input
                            .get_data_abi_mut()
                            .as_mut()
                            .unwrap()
                            .set_bytes(tx_bytes[68..68+cpu_calldatasize].to_vec());
                        // assert_eq!(thread_input.to_bytes(), tx_bytes[68..68+cpu_calldatasize].to_vec(), "set_bytes fails");

                        let calldata = hex::encode(thread_input.to_bytes().clone());
                        // #[cfg(feature = "print_txn_corpus")]
                        // {
                        //     println!("[bug] bug() hit at {:?}. Evaluating in CPU again:", thread_id);
                        // }
                        let (res, _) = fuzzer.evaluate_input_events(state, executor, manager, thread_input, true)?;
                        #[cfg(any(test, feature = "debug"))] {
                            println!("cpu vector => {:?}", hex::encode(input_vector[thread_id as usize].to_bytes()));
                        }

                        // #[cfg(feature = "print_txn_corpus")]
                        // { 
                        //     println!("Found a {:?} in GPU at thread#{:?}", res, thread_id);
                        //     println!("data changed from (CPU){:?}\n===> (GPU){:?}", hex::encode(cpu_input.to_bytes().clone()), calldata);
                        //     // exit(0);
                        // }
                    }
                    ExecuteCudaInputResult::EXECINTERESTING => {
                        println!("Found an interesting from GPU #{:?}", thread_id);
                        let mut thread_input = cpu_input.clone();
                        // println!("current CPU caller=> {:?}", thread_input.get_caller());
                        let new_caller = &mut tx_bytes[..20];
                        new_caller.reverse();
                        // println!("going to be caller=> {:?}", hex::encode(&new_caller));
                        thread_input.set_caller(EVMAddress::from_slice(&new_caller));
                        // println!("now CPU caller=> {:?}", thread_input.get_caller());
                        thread_input.set_txn_value(EVMU256::try_from_be_slice(&tx_bytes[32..64]).unwrap());
                        // println!("current CPU data=> \ntypes:{:?}\ndata:{:?}", thread_input.get_types_vec(), hex::encode(thread_input.to_bytes()));
                        thread_input
                            .get_data_abi_mut()
                            .as_mut()
                            .unwrap()
                            .set_bytes(tx_bytes[68..68+cpu_calldatasize].to_vec());
                        // assert_eq!(input_type_vec, thread_input.get_types_vec(), "type inconsistent");
                        // assert_eq!(thread_input.to_bytes(), tx_bytes[68..68+cpu_calldatasize].to_vec(), "set_bytes fails");

                        let calldata = hex::encode(thread_input.to_bytes());
                        println!("input=>{:?}", calldata);
                        let (res, _) = fuzzer.evaluate_input_events(state, executor, manager, thread_input, true)?;
                        if res == ExecuteInputResult::None {
                            println!("Unfortunately, uninteresting in CPU");
                            // exit(0);
                        } else {
                            println!("It is indeed interesting in CPU as well!");
                        }
                    }
                    _ => {
                        unreachable!();
                    }
                }
            }
            
            #[cfg(any(test, feature = "debug"))]
            println!("[-] time cost on GPU feedback {:?} us", start_time.elapsed().as_micros()); 
            #[cfg(any(test, feature = "debug"))]
            println!("[-] time cost on a round {:?} us\n", first_start_time.elapsed().as_micros());
        }

        // }
        // println!("itd = {:?}", tid);
        Ok(())
    }
}

/// Default value, how many iterations each stage gets, as an upper bound.
/// It may randomly continue earlier.
pub static DEFAULT_MUTATIONAL_MAX_ITERATIONS: u64 = 128;

/// The default mutational stage
#[derive(Clone, Debug)]
pub struct StdGPUMutationalStage<E, EM, I, M, S, Z>
where
    M: Mutator<I, S>,
    I: Input + Serialize + EVMInputT + 'static,
    S: HasClientPerfMonitor
        + HasCorpus<I>
        + HasRand
        + HasExecutions,
    Z: Evaluator<E, EM, I, S>,
{
    mutator: M,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(E, EM, I, S, Z)>,
}

impl<E, EM, I, M, S, Z> MutationalStage<E, EM, I, M, S, Z> for StdGPUMutationalStage<E, EM, I, M, S, Z>
where
    M: Mutator<I, S>,
    I: Input + Serialize + EVMInputT + VMInputT<EVMState, EVMAddress, EVMAddress> + 'static,
    S: HasClientPerfMonitor
        + HasCorpus<I>
        + HasRand
        + HasStartTime
        + HasExecutions,
    Z: Evaluator<E, EM, I, S>,
{
    /// The mutator, added to this stage
    #[inline]
    fn mutator(&self) -> &M {
        &self.mutator
    }

    /// The list of mutators, added to this stage (as mutable ref)
    #[inline]
    fn mutator_mut(&mut self) -> &mut M {
        &mut self.mutator
    }

    /// Gets the number of iterations as a random number
    fn iterations(&self, state: &mut S, _corpus_idx: usize) -> Result<usize, Error> {
        Ok(1 + state.rand_mut().below(DEFAULT_MUTATIONAL_MAX_ITERATIONS) as usize)
    }
}

impl<E, EM, I, M, S, Z> Stage<E, EM, S, Z> for StdGPUMutationalStage<E, EM, I, M, S, Z>
where
    // VS: Default + VMStateT,
    // Addr: Serialize + DeserializeOwned + Debug + Clone,
    // Loc: Serialize + DeserializeOwned + Debug + Clone,
    M: Mutator<I, S>,
    I: Input + Serialize + EVMInputT + VMInputT<EVMState, EVMAddress, EVMAddress> + 'static,
    S: HasClientPerfMonitor
        + HasCorpus<I>
        + HasRand
        + HasStartTime
        + HasExecutions,
    Z: Evaluator<E, EM, I, S>,
{
    #[inline]
    #[allow(clippy::let_and_return)]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error> {
        // run CPU mode at least five minutes
        let ret = if unsafe { GPU_ENABLE } && current_time().checked_sub(*state.start_time()).unwrap().as_secs() > STATS_CPU_DEFAULT {
        // let ret = if unsafe { GPU_ENABLE } {
            // println!("===================== GPU enabled ====================");
            self.perform_multiple_mutational(fuzzer, executor, state, manager, corpus_idx)
        } else {
            // default 
            self.perform_mutational(fuzzer, executor, state, manager, corpus_idx)
        };
        // one to multiple GPU threads
        // let ret = self.perform_one_mutational(fuzzer, executor, state, manager, corpus_idx);

        // multiple to multiple GPU threads
        // let ret = if *state.executions() < 3000000 {
        //     // default
        //     self.perform_mutational(fuzzer, executor, state, manager, corpus_idx)
        // } else {
        //     // GPU mode
        //     self.perform_multiple_mutational(fuzzer, executor, state, manager, corpus_idx)
        // };

        #[cfg(feature = "introspection")]
        state.introspection_monitor_mut().finish_stage();

        ret
    }
}

impl<E, EM, I, M, S, Z> StdGPUMutationalStage<E, EM, I, M, S, Z>
where
    M: Mutator<I, S>,
    I: Input + Serialize + EVMInputT + 'static,
    S: HasClientPerfMonitor
        + HasCorpus<I>
        + HasRand
        + HasExecutions,
    Z: Evaluator<E, EM, I, S>,
{
    /// Creates a new default mutational stage
    pub fn new(mutator: M) -> Self {
        Self {
            mutator,
            phantom: PhantomData,
        }
    }
}

#[cfg(feature = "python")]
#[allow(missing_docs)]
/// `StdGPUMutationalStage` Python bindings
pub mod pybind {
    use pyo3::prelude::*;

    use crate::{
        events::pybind::PythonEventManager,
        executors::pybind::PythonExecutor,
        fuzzer::pybind::PythonStdFuzzer,
        inputs::BytesInput,
        mutators::pybind::PythonMutator,
        stages::{pybind::PythonStage, StdGPUMutationalStage},
        state::pybind::PythonStdState,
    };

    #[pyclass(unsendable, name = "StdGPUMutationalStage")]
    #[derive(Debug)]
    /// Python class for StdGPUMutationalStage
    pub struct PythonStdGPUMutationalStage {
        /// Rust wrapped StdGPUMutationalStage object
        pub inner: StdGPUMutationalStage<
            PythonExecutor,
            PythonEventManager,
            BytesInput,
            PythonMutator,
            PythonStdState,
            PythonStdFuzzer,
        >,
    }

    #[pymethods]
    impl PythonStdGPUMutationalStage {
        #[new]
        fn new(mutator: PythonMutator) -> Self {
            Self {
                inner: StdGPUMutationalStage::new(mutator),
            }
        }

        fn as_stage(slf: Py<Self>) -> PythonStage {
            PythonStage::new_std_mutational(slf)
        }
    }

    /// Register the classes to the python module
    pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
        m.add_class::<PythonStdGPUMutationalStage>()?;
        Ok(())
    }
}
