/// Implements fuzzing logic for ItyFuzz

use crate::{
    input::VMInputT,
    state::{HasCurrentInputIdx, HasInfantStateState, HasItyState, InfantStateState},
    state_input::StagedVMState, evm::{types::EVMAddress, input::EVMInputT, abi::BoxedABI, mutator}, scheduler::HasVote,
};
use std::{collections::hash_map::DefaultHasher, io::Read, ops::Deref, borrow::BorrowMut};
use std::collections::HashMap;
use std::fmt::Debug;
use std::fs::File;
use std::io::Write;
use std::ptr;
use core::{
    cmp::{max, min},
    cell::RefCell,
};

use std::time::{SystemTime, UNIX_EPOCH};
use std::path::Path;
use std::process::exit;
use std::{marker::PhantomData, time::Duration};

use crate::evm::vm::EVMState;
use crate::evm::oracles::erc20::ORACLE_OUTPUT;
use crate::generic_vm::vm_executor::MAP_SIZE;
use crate::generic_vm::vm_state::VMStateT;
use crate::state::{HasCaller, HasExecutionResult};
use crate::tracer::build_basic_txn;
use libafl::{
    fuzzer::Fuzzer,
    mark_feature_time,
    prelude::{
        current_time, Corpus, Event, EventConfig, EventManager, Executor, Feedback, HasObservers, 
        State, HasRand, Rand, HasMaxSize, ObserversTuple, Testcase,
    },
    schedulers::Scheduler,
    stages::StagesTuple,
    start_timer,
    state::{HasClientPerfMonitor, HasCorpus, HasExecutions, HasMetadata, HasSolutions},
    Error, Evaluator, ExecuteInputResult,
    inputs::Input,
};
use nix::sys::stat;
use revm_primitives::bitvec::macros::internal::funty::{Fundamental, Numeric};
use serde_traitobject::Any;

use crate::evm::host::{JMP_MAP, BRANCH_DISTANCE_INTERESTING, EXPLORED_INS, EXPLORED_EDGE,BUGTAGS,LASTCALLPC,RECALLSLOT};
use crate::evm::types::EVMU256;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::hash::{Hash, Hasher};

use crate::evm::input::EVMInput;

const STATS_TIMEOUT_DEFAULT: Duration = Duration::from_millis(4000);
use crate::evm::config::{RUN_FOREVER, DUMP_CORPUS};

/// A fuzzer that implements ItyFuzz logic using LibAFL's [`Fuzzer`] trait
///
/// CS: The scheduler for the input corpus
/// IS: The scheduler for the infant state corpus
/// F: The feedback for the input corpus (e.g., coverage map)
/// IF: The feedback for the infant state corpus (e.g., comparison, etc.)
/// I: The VM input type
/// OF: The objective for the input corpus (e.g., oracles)
/// S: The fuzzer state type
/// VS: The VM state type
/// Addr: The address type (e.g., H160)
/// Loc: The call target location type (e.g., H160)
#[derive(Debug)]
pub struct ItyFuzzer<'a, VS, Loc, Addr, Out, CS, IS, F, IF, I, OF, S, OT>
where
    CS: Scheduler<I, S>,
    IS: Scheduler<StagedVMState<Loc, Addr, VS>, InfantStateState<Loc, Addr, VS>>,
    F: Feedback<I, S>,
    IF: Feedback<I, S>,
    I: VMInputT<VS, Loc, Addr>,
    OF: Feedback<I, S>,
    S: HasClientPerfMonitor,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
{
    /// The scheduler for the input corpus
    scheduler: CS,
    /// The feedback for the input corpus (e.g., coverage map)
    feedback: F,
    /// The feedback for the infant state corpus (e.g., comparison, etc.)
    infant_feedback: IF,
    /// The scheduler for the infant state corpus
    infant_scheduler: &'a IS,
    /// The objective for the input corpus (e.g., oracles)
    objective: OF,
    /// Map from hash of a testcase can do (e.g., coverage map) to the (testcase idx, fav factor)
    /// Used to minimize the corpus
    minimizer_map: HashMap<u64, (usize, f64)>,
    phantom: PhantomData<(I, S, OT, VS, Loc, Addr, Out)>,
    // corpus path
    corpus_path: String,
    /// the code coverage in cuda
    cuda_cov: u64,
    /// map from a testcase can do (distance) to the testcase idx.
    distance_map: HashMap<usize, usize>,
}

impl<'a, VS, Loc, Addr, Out, CS, IS, F, IF, I, OF, S, OT>
    ItyFuzzer<'a, VS, Loc, Addr, Out, CS, IS, F, IF, I, OF, S, OT>
where
    CS: Scheduler<I, S>,
    IS: Scheduler<StagedVMState<Loc, Addr, VS>, InfantStateState<Loc, Addr, VS>>,
    F: Feedback<I, S>,
    IF: Feedback<I, S>,
    I: VMInputT<VS, Loc, Addr>,
    OF: Feedback<I, S>,
    S: HasClientPerfMonitor,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
{
    /// Creates a new ItyFuzzer
    pub fn new(
        scheduler: CS,
        infant_scheduler: &'a IS,
        feedback: F,
        infant_feedback: IF,
        objective: OF,
        corpus_path: String,
    ) -> Self {
        Self {
            scheduler,
            feedback,
            infant_feedback,
            infant_scheduler,
            objective,
            corpus_path,
            minimizer_map: Default::default(),
            phantom: PhantomData,
            cuda_cov: 0,
            distance_map: Default::default(),
        }
    }

    /// Called every time a new testcase is added to the corpus
    /// Setup the minimizer map
    pub fn on_add_corpus(
        &mut self,
        input: &I,
        coverage: &[u8; MAP_SIZE],
        testcase_idx: usize,
    ) -> () {
        let mut hasher = DefaultHasher::new();
        coverage.hash(&mut hasher);
        let hash = hasher.finish();
        self.minimizer_map
            .insert(hash, (testcase_idx, input.fav_factor()));
    }

    /// Called every time a testcase is replaced for the corpus
    /// Update the minimizer map
    pub fn on_replace_corpus(
        &mut self,
        (hash, new_fav_factor, _): (u64, f64, usize),
        new_testcase_idx: usize,
    ) -> () {
        let res = self.minimizer_map.get_mut(&hash).unwrap();
        res.0 = new_testcase_idx;
        res.1 = new_fav_factor;
    }

    /// Determine if a testcase should be replaced based on the minimizer map
    /// If the new testcase has a higher fav factor, replace the old one
    /// Returns None if the testcase should not be replaced
    /// Returns Some((hash, new_fav_factor, testcase_idx)) if the testcase should be replaced
    pub fn should_replace(
        &self,
        input: &I,
        coverage: &[u8; MAP_SIZE],
    ) -> Option<(u64, f64, usize)> {
        let mut hasher = DefaultHasher::new();
        coverage.hash(&mut hasher);
        let hash = hasher.finish();
        // if the coverage is same
        if let Some((testcase_idx, fav_factor)) = self.minimizer_map.get(&hash) {
            let new_fav_factor = input.fav_factor();
            // if the new testcase has a higher fav factor, replace the old one
            if new_fav_factor > *fav_factor {
                return Some((hash, new_fav_factor, testcase_idx.clone()));
            }
        }
        None
    }
}

/// Implement fuzzer trait for ItyFuzzer
impl<'a, VS, Loc, Addr, Out, CS, IS, E, EM, F, IF, I, OF, S, ST, OT> Fuzzer<E, EM, I, S, ST>
    for ItyFuzzer<'a, VS, Loc, Addr, Out, CS, IS, F, IF, I, OF, S, OT>
where
    CS: Scheduler<I, S>,
    IS: Scheduler<StagedVMState<Loc, Addr, VS>, InfantStateState<Loc, Addr, VS>>,
    E: Executor<EM, I, S, Self> + HasObservers<I, OT, S>,
    OT: ObserversTuple<I, S> + serde::Serialize + serde::de::DeserializeOwned,
    EM: EventManager<E, I, S, Self>,
    F: Feedback<I, S>,
    IF: Feedback<I, S>,
    I: Input + VMInputT<VS, Loc, Addr> + Serialize + EVMInputT + 'static,
    OF: Feedback<I, S>,
    // S: HasClientPerfMonitor + HasExecutions + HasMetadata + HasCurrentInputIdx,
    S: State
        + HasRand
        + HasMaxSize
        + HasCaller<Addr>
        + HasClientPerfMonitor
        + HasExecutions 
        + HasMetadata
        + HasCurrentInputIdx
        + HasCorpus<I>
        + HasSolutions<I>
        + HasInfantStateState<Loc, Addr, VS>
        + HasItyState<Loc, Addr, VS>
        + HasItyState<EVMAddress, EVMAddress, EVMState>
        + HasExecutionResult<Loc, Addr, VS, Out>,
        Out: Default,

        // E: Executor<EM, I, S, Self> + HasObservers<I, OT, S>,
        // OT: ObserversTuple<I, S> + serde::Serialize + serde::de::DeserializeOwned,
        // EM: EventManager<E, I, S, Self>,
        // S: HasClientPerfMonitor
        //     + HasCorpus<I>
        //     + HasSolutions<I>
        //     + HasInfantStateState<Loc, Addr, VS>
        //     + HasItyState<Loc, Addr, VS>
        //     + HasExecutionResult<Loc, Addr, VS, Out>
        //     + HasExecutions,
        // VS: Default + VMStateT,
        // Addr: Serialize + DeserializeOwned + Debug + Clone,
        // Loc: Serialize + DeserializeOwned + Debug + Clone,

    ST: StagesTuple<E, EM, S, Self> + ?Sized,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
{
    /// Fuzz one input
    fn fuzz_one(
        &mut self,
        stages: &mut ST,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<usize, libafl::Error> {
        let idx = self.scheduler.next(state)?;
        state.set_current_input_idx(idx);

        // TODO: if the idx input is a concolic input returned by the solver
        // we should not perform all stages.

        stages
            .perform_all(self, executor, state, manager, idx)
            .expect("perform_all failed");
        manager.process(self, state, executor)?;
        // println!("state.corpus() = {:?}", state.corpus().count());
        // for ttt in 0..state.corpus().count() {
        //     let input = state.corpus().get(ttt)?.clone().into_inner().input().as_ref().unwrap().clone();
        //     input.get_state().get_s(&input.get_evm_contract());
        //     println!("input => {:?}", input.pretty_txn());
        // }
        // println!("----------------------------------------------------");
        // exit(0);
        Ok(idx)
    }

    /// Fuzz loop
    fn fuzz_loop(
        &mut self,
        stages: &mut ST,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<usize, Error> {
        let mut last = current_time();
        // now report stats to manager every 0.1 sec
        let monitor_timeout = STATS_TIMEOUT_DEFAULT;
        loop {
            self.fuzz_one(stages, executor, state, manager)?;
            last = manager.maybe_report_progress(state, last, monitor_timeout)?;
        }
    }

    // /// Fuzz loop
    // fn fuzz_loop(
    //     &mut self,
    //     stages: &mut ST,
    //     executor: &mut E,
    //     state: &mut S,
    //     manager: &mut EM,
    // ) -> Result<usize, Error> {
    //     let mut last = current_time();
    //     // now report stats to manager every 1 sec
    //     let monitor_timeout = Duration::from_millis(1000);

    //     // run initial seeds in EVM
    //     let initial_corpus_size = state.corpus().count();
    //     // let mut vm_state = StagedVMState::new_with_state(EVMState::new());
    //     for idx in 0..initial_corpus_size {
    //         println!("-------------------- idx = {:?}; size = {:?} --------------- ", idx, state.corpus().count());
    //         state.set_current_input_idx(idx);
    //         let mut input = state.corpus().get(idx)?.clone().into_inner().input().as_ref().unwrap().clone();
    //         if !input.get_staged_state().initialized {
    //             let concrete = state.get_infant_state(self.infant_scheduler).unwrap();
    //             input.set_staged_state(concrete.1, concrete.0);
    //         }
    //         let _ = self.evaluate_input_events(state, executor, manager, input, false);
    //         // input.get_state().get_s(&input.get_evm_contract());
    //     }
    //     println!("===================================== GPU Enabled =======================================");
    //     #[link(name = "runner")]
    //     extern "C" {
    //         fn cuLoadSeed(value_ptr: *const u8, data_ptr: *const u8, data_size: u32, thread: u32);
    //         fn cuEvalTxn(nwrap: u32);
    //         fn getCudaExecRes(pcov: *const u64, pbug: *const u64) -> bool;
    //         fn isCudaInteresting(tid: u32) -> u8;
    //         fn cuDumpStorage(threadId: u32);
    //         fn cuLoadStorage(src: *const u8, slotCnt: u32, wrapi: u32);
    //     }
    //     loop {           
    //         let corpus_size = state.corpus().count();
    //         let wrap_count = min(corpus_size, NJOBS as usize);
    //         let slot_count = NJOBS as usize / wrap_count;
    //         // println!("Corpus Size {:?}; wrap_count {:?}; slot_count {:?}", corpus_size, wrap_count, slot_count);

    //         // Fuzz one batch of inputs
    //         let mut input_vec: Vec<EVMInput> = Vec::new();

    //         let mut tid = 0;
    //         for wrap_i in 0..wrap_count {
    //             let corpus_idx = self.scheduler.next(state)?;

    //             // println!("corpus_idx = {:?}; corpus_size = {:?}", corpus_idx, corpus_size);
    //             state.set_current_input_idx(corpus_idx);
    //             // let corpus_item = state.corpus().get(corpus_idx)?;
    //             // let testcase = corpus_item.clone().into_inner();
    //             // // we only need testcase with calldatasize > 0
    //             // if testcase.input().is_none() {
    //             //     continue;
    //             // }
    //             // let mut input = testcase.input().as_ref().unwrap().clone();
    //             let mut input = state
    //                 .corpus()
    //                 .get(corpus_idx)?
    //                 .borrow_mut()
    //                 .load_input()?
    //                 .clone();
                

    //             // let empty = match input.get_data_abi() {
    //             //     None => true,
    //             //     Some(ref abi) => abi.get_bytes_vec().len() == 0,
    //             // };
    //             // if empty { 
    //             //     // let _ = self.evaluate_input(state, executor, manager, input);
    //             //     continue; 
    //             // }

    //             if !input.get_staged_state().initialized {
    //                 let concrete = state.get_infant_state(self.infant_scheduler).unwrap();
    //                 input.set_staged_state(concrete.1, concrete.0);
    //             }
    //             // println!("\n\ncorpus[{:?}] initiated={:?}  = {:?}", cidx, input.get_staged_state().initialized, input);
    //             // println!("===> current new get_data_abi => {:?}", input.get_data_abi());
    //             // input.get_state().get_s(&input.get_evm_contract());

    //             if wrap_i == 0 {
    //                 input.set_evm_env();
    //             }
    //             if let Some(storage) = input.as_any().downcast_ref::<EVMInput>().unwrap().get_state().get(&input.get_evm_contract()) {
    //                 let mut bytes = Vec::new();
    //                 // println!("storage content before executing input=>");
    //                 for (key, value) in storage {
    //                     // for (key, value) in storage {
    //                     //     println!("{:#x}: {:#x}", key, value);
    //                     // }
    //                     let slot = [key.as_le_bytes(), value.as_le_bytes()].concat();
    //                     bytes.extend(slot);
    //                 }
    //                 unsafe{ cuLoadStorage(bytes.as_ptr(), storage.len().as_u32(), wrap_i as u32); }
    //             } else {
    //                 unsafe{ cuLoadStorage(ptr::null(), 0, wrap_i as u32); }
    //             }
                
    //             let itr = if wrap_i == wrap_count - 1 {
    //                 slot_count + (NJOBS as usize % wrap_count)
    //             } else {
    //                 slot_count
    //             };
    //             for _ in 0..itr {
    //                 input.mutate(state);
    //                 let calldata = 
    //                     match input.get_data_abi() {
    //                         None => input.get_direct_data(),
    //                         Some(ref abi) => abi.get_bytes(), // function hash + encoded args
    //                     };
    //                 let calldatasize = calldata.len();
    //                 // println!("tid#{:?} calldata:=> {:?}\n", tid, hex::encode(calldata.clone()));     
    //                 input_vec.push(input.as_any().downcast_ref::<EVMInput>().unwrap().clone());

    //                 let callvalue: [u8; 32] = input.get_txn_value().unwrap_or(EVMU256::ZERO).to_le_bytes();
    //                 unsafe {
    //                     cuLoadSeed(callvalue.as_ptr(), calldata.as_ptr(), calldatasize as u32, tid as u32);
    //                 }
    //                 tid += 1;
    //             }
    //         }

    //         *state.executions_mut() += tid as usize; 
    //         // run
    //         unsafe {
    //             cuEvalTxn(wrap_count as u32);
    //         }
    //         unsafe {
    //             let mut _cov : u64 = 0; // remove
    //             let mut _buggy : u64 = 0; // remove
    //             let _ = getCudaExecRes(&_cov, &_buggy);
    //         }

    //         for (thread_id, tmp_in) in input_vec.iter_mut().enumerate() {
    //             let thread_input = tmp_in.as_any_mut().downcast_ref::<I>().unwrap().clone();
    //             let hnb : ExecuteCudaInputResult = unsafe { 
    //                 let r = isCudaInteresting(thread_id as u32);
    //                 // println!("hnb[{:?}] = {:?}", thread_id, r);
    //                 std::mem::transmute(r)
    //             };
    //             match hnb {
    //                 ExecuteCudaInputResult::EXECNONE => {
    //                     // println!("============= EXEC NONE Seed =============");
    //                     let _ = self.evaluate_input_events(state, executor, manager, thread_input, true);
    //                     continue;
    //                 }
    //                 ExecuteCudaInputResult::EXECREVERTED => {
    //                     continue;
    //                 }
    //                 ExecuteCudaInputResult::EXECBUGGY => {
    //                     // unsafe{ cuDumpStorage(thread_id as u32); }
    //                     #[cfg(feature = "print_txn_corpus")]
    //                     {   
    //                         println!("[bug] bug() hit at {:?}", thread_id);
    //                         let txn = build_basic_txn(&thread_input, &state.get_execution_result());
    //                         state.get_execution_result_mut().new_state.trace.from_idx = Some(thread_input.get_state_idx());
    //                         state
    //                             .get_execution_result_mut()
    //                             .new_state
    //                             .trace
    //                             .add_txn(txn);
    //                         report_vulnerability(
    //                             unsafe {ORACLE_OUTPUT.clone()},
    //                         );
    //                         unsafe {
    //                             println!("Oracle: {}", ORACLE_OUTPUT);
    //                         }
    //                         println!(
    //                             "Found a solution! trace: {}",
    //                             state
    //                                 .get_execution_result()
    //                                 .new_state
    //                                 .trace
    //                                 .clone()
    //                                 .to_string(state)
    //                         );
    //                     }
    //                     self.feedback.discard_metadata(state, &thread_input)?;

    //                     // The input is a solution, add it to the respective corpus
    //                     let mut testcase = Testcase::new(thread_input);
    //                     self.objective.append_metadata(state, &mut testcase)?;
    //                     state.solutions_mut().add(testcase)?;
    //                     // exit(0);
    //                 }
    //                 ExecuteCudaInputResult::EXECINTERESTING => {
    //                     // #[cfg(feature = "print_txn_corpus")]
    //                     // {
    //                         // println!("======== New Corpus Item From GPU#{:?} ========", thread_id);
    //                         // unsafe{ cuDumpStorage(thread_id as u32); }
    //                         // thread_input.get_state().get_s(&thread_input.get_evm_contract());
    //                         // println!("==========================================");
    //                     // }
    //                     // add the cuda-varient to the corpus
    //                     // let mut cu_tc = Testcase::new(thread_input.clone()) as Testcase<I>;
    //                     // self.feedback.append_metadata(state, &mut cu_tc)?;
    //                     // let idx = state.corpus_mut().add(cu_tc)?;
    //                     // self.scheduler.on_add(state, idx)?;
    //                     // let _ = self.evaluate_input(state, executor, manager, thread_input);
    //                     let _ = self.evaluate_input_events(state, executor, manager, thread_input, true);
    //                 }
    //                 _ => {
    //                     unreachable!();
    //                 }
    //             }
    //         }
    //         last = manager.maybe_report_progress(state, last, monitor_timeout)?;
    //         // exit(0);
    //     }
    // }
}

#[cfg(feature = "print_txn_corpus")]
pub static mut DUMP_FILE_COUNT: usize = 0;

pub enum ExecuteCudaInputResult {
    /// No special input
    EXECNONE = 0, 
    /// Fail to execute this cuda input, i.e.,
    EXECREVERTED, 
    /// This input should be stored in the corpus
    EXECINTERESTING, 
    /// This input leads to a solution
    EXECBUGGY,
    /// mininer distance
    EXECLESSDISTANCE, 
}

// implement evaluator trait for ItyFuzzer
impl<'a, VS, Loc, Addr, Out, E, EM, I, S, CS, IS, F, IF, OF, OT> Evaluator<E, EM, I, S>
    for ItyFuzzer<'a, VS, Loc, Addr, Out, CS, IS, F, IF, I, OF, S, OT>
where
    CS: Scheduler<I, S>,
    IS: Scheduler<StagedVMState<Loc, Addr, VS>, InfantStateState<Loc, Addr, VS>>
        + HasVote<StagedVMState<Loc, Addr, VS>, InfantStateState<Loc, Addr, VS>>,
    F: Feedback<I, S>,
    IF: Feedback<I, S>,
    E: Executor<EM, I, S, Self> + HasObservers<I, OT, S>,
    OT: ObserversTuple<I, S> + serde::Serialize + serde::de::DeserializeOwned,
    EM: EventManager<E, I, S, Self>,
    I: VMInputT<VS, Loc, Addr>,
    OF: Feedback<I, S>,
    S: HasClientPerfMonitor
        + HasCorpus<I>
        + HasSolutions<I>
        + HasInfantStateState<Loc, Addr, VS>
        + HasItyState<Loc, Addr, VS>
        + HasExecutionResult<Loc, Addr, VS, Out>
        + HasExecutions,
    VS: Default + VMStateT,
    Addr: Serialize + DeserializeOwned + Debug + Clone,
    Loc: Serialize + DeserializeOwned + Debug + Clone,
    Out: Default,
{
    /// Evaluate input (execution + feedback + objectives)
    fn evaluate_input_events(
        &mut self,
        state: &mut S,
        executor: &mut E,
        manager: &mut EM,
        input: I,
        send_events: bool,
    ) -> Result<(ExecuteInputResult, Option<usize>), Error> {
        // {
        //     println!("============= evaluating in EVM again =============");
        //     let tx_trace = state
        //         .get_execution_result()
        //         .new_state
        //         .trace
        //         .clone();
        //     let txn_text = tx_trace.to_string(state);
        //     let data = format!(
        //         "Reverted? {} \n Txn: {}",
        //         state.get_execution_result().reverted,
        //         txn_text
        //     );
        //     println!("{}", data);
        //     // input.get_state().get_s(&input.get_evm_contract());
        // }
        start_timer!(state);
        executor.observers_mut().pre_exec_all(state, &input)?;
        mark_feature_time!(state, PerfFeature::PreExecObservers);

        // execute the input
        start_timer!(state);
        let exitkind = executor.run_target(self, state, manager, &input)?;
        unsafe {
            LASTCALLPC = 0;
            RECALLSLOT.clear();
        }
        mark_feature_time!(state, PerfFeature::TargetExecution);
        *state.executions_mut() += 1;

        start_timer!(state);
        executor
            .observers_mut()
            .post_exec_all(state, &input, &exitkind)?;
        mark_feature_time!(state, PerfFeature::PostExecObservers);

        let observers = executor.observers();
        let reverted = state.get_execution_result().reverted;

        // get new stage first
        let is_infant_interesting = self
            .infant_feedback
            .is_interesting(state, manager, &input, observers, &exitkind)?;
        // println!("is_infant_interesting => {:?}", is_infant_interesting);

        let is_solution = self
            .objective
            .is_interesting(state, manager, &input, observers, &exitkind)?;

        // println!("is_solution => {:?}", is_solution);
        // add the trace of the new state
        #[cfg(any(feature = "print_infant_corpus", feature = "print_txn_corpus"))]
        {
            let txn = build_basic_txn(&input, &state.get_execution_result());
            state.get_execution_result_mut().new_state.trace.from_idx = Some(input.get_state_idx());
            state
                .get_execution_result_mut()
                .new_state
                .trace
                .add_txn(txn);
        }

        // add the new VM state to infant state corpus if it is interesting
        if is_infant_interesting && !reverted {
            let idx_infant_state = state.add_infant_state(
                &state.get_execution_result().new_state.clone(),
                self.infant_scheduler,
            ).unwrap();
            // println!("==========Interesting infant states #{:?} ==========", idx_infant_state);
            // load initial storage one by one (heavy mode)
            // #[cfg(feature = "cuda_snapshot_storage")] 
            // {   
            //     // println!("changed => len = {:?}: {:?}", a.len(), a);
            //     // let k = state.get_execution_result().new_state.clone();
            //     // println!("==========Interesting infant states ========== \n{:?}\n------\n{:?}\n==========", k.state.as_any().downcast_ref::<EVMState>().unwrap());
            //     #[link(name = "runner")]
            //     extern "C" {
            //         fn cuLoadStorage(src: *const u8, slotCnt: u32, wrapi: u32);
            //         fn cuSetStorageMap(s_idx: u32, s_pos: u32);
            //     }
            //     let storage_pos = self.infant_scheduler.get_is_state_used(state.get_infant_state_state(), idx_infant_state);
            //     if unsafe{ GPU_ENABLE } && storage_pos >= 0 {
            //         unsafe { cuSetStorageMap(idx_infant_state as u32, storage_pos as u32);}
            //         let executed_evm_state = state
            //         .get_execution_result()
            //         .new_state
            //         .state
            //         .as_any()
            //         .downcast_ref::<EVMState>()
            //         .unwrap();
            //         if let Some(storage) = executed_evm_state.get(&input.get_evm_contract()) {
            //             let mut bytes = Vec::new();
            //             // println!("========== infant state ==========\n=> {:?}\n==========", storage);
            //             for (key, value) in storage {
            //                 let slot = [key.as_le_bytes(), value.as_le_bytes()].concat();
            //                 bytes.extend(slot);
            //             }
            //             unsafe{ cuLoadStorage(bytes.as_ptr(), storage.len() as u32, storage_pos as u32); }
            //         } else {
            //             unsafe{ cuLoadStorage(ptr::null(), 0, storage_pos as u32); }
            //         }
            //     }
            // }
        }

        let mut res = ExecuteInputResult::None;
        if is_solution && !reverted {
            res = ExecuteInputResult::Solution;
        } else {
            // println!("is_interesting begin");
            let is_corpus = self
                .feedback
                .is_interesting(state, manager, &input, observers, &exitkind)?;
            // println!("is_interesting end => {:?}", is_corpus);
            if is_corpus {
                res = ExecuteInputResult::Corpus;
            }
        }
        // aggresive state mode
        if res == ExecuteInputResult::None && unsafe { BRANCH_DISTANCE_INTERESTING } {
            // add to the corpus
            res = ExecuteInputResult::Corpus;
        }

        if unsafe { DUMP_CORPUS } && res != ExecuteInputResult::None {
            // Debugging prints
            #[cfg(feature = "print_txn_corpus")]
            {
                unsafe {
                    DUMP_FILE_COUNT += 1;
                }

                let tx_trace = state
                    .get_execution_result()
                    .new_state
                    .trace
                    .clone();
                // let txn_text = tx_trace.to_string(state);

                let txn_text_replayable = tx_trace.to_file_str(state);

                // let data = format!(
                //     "Reverted? {} \n Txn: {}",
                //     state.get_execution_result().reverted,
                //     txn_text
                // );
                // println!("============= New Corpus Item =============");
                // println!("{}", data);
                // println!("==========================================");

                // write to file
                let path = Path::new(self.corpus_path.as_str());
                if !path.exists() {
                    std::fs::create_dir(path).unwrap();
                }
                // let mut file =
                //     File::create(format!("{}/{}", self.corpus_path.as_str(), unsafe { DUMP_FILE_COUNT })).unwrap();
                // file.write_all(data.as_bytes()).unwrap();
                let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards").as_nanos();

                let mut replayable_file =
                    File::create(format!("{}/{}_{}_replayable", self.corpus_path.as_str(), unsafe { DUMP_FILE_COUNT }, timestamp)).unwrap();
                replayable_file.write_all(txn_text_replayable.as_bytes()).unwrap();
                
                let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards").as_nanos();

                // deployment/maze-10/maze-10(0x6b773032d99fb9aad6fc267651c446fa7f9301af): 85.13% (18040) Instruction Covered, 78.28% (1824) Branch Covered 1697701037735016082

                println!(
                    "deployment/contract/contract(0x6b773032d99fb9aad6fc267651c446fa7f9301af): 0.00% ({}) Instruction Covered, 0.00% ({}) Branch Covered {}",
                    unsafe { EXPLORED_INS },
                    unsafe { EXPLORED_EDGE },
                    timestamp,
                );
            }
        }
        match res {
            // not interesting input, just check whether we should replace it due to better fav factor
            ExecuteInputResult::None => {
            //     let cuda_input = input.clone();
            //     let calldata = 
            //     match cuda_input.get_data_abi() {
            //         None => input.get_direct_data(),
            //         Some(ref abi) => abi.get_bytes(),
            //     };
            //     let calldatasize = calldata.len();
        
            //     // execute inside the GPU
            //     #[cfg(feature = "cuda")]
            //     {   
            //         // println!("[+] Cuda enabled");
            //         let begin_cuda_time = current_time();
            //         // if *state.executions() > 200000 && res == ExecuteInputResult::None 
            //         if calldata.len() > 0 && *state.executions() > 0 {
            //             // println!("Cuda is trying to solve constraints...");
            //             *state.executions_mut() += NJOBS as usize;
            //             #[link(name = "runner")]
            //             extern "C" {
            //                 fn cuExtSeeds(rawSeed: *const u8, size: u32);
            //                 fn cuEvalTxn(size: u32);
            //                 fn cuMutate(calldasize: u32, argTypes: *const u8, argTypesLen: u32);
            //                 fn getCudaExecRes(pcov: *const u64, pbug: *const u64) -> bool;
            //                 fn gainCov(tid: u32, RawSeed: *mut u8) -> u8;
            //                 fn cuDumpStorage(threadId: u32);
            //             }

            //             // load environmental variables and storage to cuda context
            //             cuda_input.set_evm_env();
            //             cuda_input.get_state().get_s(&cuda_input.get_evm_contract());

            //             let input_type_vec = cuda_input.as_any()
            //                 .downcast_ref::<EVMInput>()
            //                 .unwrap().get_types_vec();

            //             unsafe {
            //                 cuExtSeeds(calldata.as_ptr(), calldatasize as u32);
            //                 cuMutate(calldatasize as u32, input_type_vec.as_ptr(), input_type_vec.len() as u32);
            //                 cuEvalTxn(calldatasize as u32);
            //             }
            //             let end_cuda_execute = current_time();
            //             // println!("executed in CUDA costs {:?}", end_cuda_execute - begin_cuda_time);

            //             unsafe {
            //                 let mut new_cuda_cov : u64 = 0; // remove
            //                 let mut buggy_tid : u64 = 0; // remove
            //                 let _ = getCudaExecRes(&new_cuda_cov, &buggy_tid);
            //             }

            //             let mut tx_bytes:[u8; SEED_SIZE] = [0; SEED_SIZE];
                        
            //             for tid in 0..NJOBS {
            //                 tx_bytes.fill(0);
            //                 let hnb : ExecuteCudaInputResult = unsafe { 
            //                     let r = gainCov(tid, tx_bytes.as_mut_ptr());
            //                     std::mem::transmute(r)
            //                 };

            //                 match hnb {
            //                     ExecuteCudaInputResult::EXECNONE => {
            //                         continue;
            //                     }
            //                     ExecuteCudaInputResult::EXECREVERTED => {
            //                         continue;
            //                     }
            //                     ExecuteCudaInputResult::EXECBUGGY => {
            //                         // bug detected
            //                         println!("========= Bug detected in thread {:?} ==========", tid);
            //                         // unsafe{ cuDumpStorage(tid as u32); }
            //                         #[cfg(any(feature = "print_cuda_corpus"))]
            //                         {   
            //                             let mut gpu_input = cuda_input.clone();
                                        
            //                             // println!(
            //                             //     "Debug a solution! trace: {}",
            //                             //     state
            //                             //         .get_execution_result()
            //                             //         .new_state
            //                             //         .trace
            //                             //         .clone()
            //                             //         .to_string(state)
            //                             // );
            //                             //let original_data = gpu_input.get_data_abi().unwrap().get_bytes();

            //                             gpu_input
            //                                     .get_data_abi_mut()
            //                                     .as_mut()
            //                                     .unwrap()
            //                                     .set_bytes(tx_bytes.to_vec());
            //                             gpu_input.set_cuda_input(vec![]); // TODO
            //                             /*let after_bytes = gpu_input.get_data_abi().unwrap().get_bytes();
            //                             println!(
            //                                 "calldata:=> {:?}\nabi-data:=> {:?}\nafttdata:=> {:?}",
            //                                 hex::encode(tx_bytes.to_vec()),
            //                                 hex::encode(original_data.clone()),
            //                                 hex::encode(after_bytes),
            //                             );
            //                             */

            //                             let txn = build_basic_txn(&gpu_input, &state.get_execution_result());
            //                             state.get_execution_result_mut().new_state.trace.from_idx = Some(gpu_input.get_state_idx());
            //                             state
            //                                 .get_execution_result_mut()
            //                                 .new_state
            //                                 .trace
            //                                 .renew_last_txn(txn);
            //                             report_vulnerability(
            //                                 unsafe {ORACLE_OUTPUT.clone()},
            //                             );
            //                             unsafe {
            //                                 println!("Oracle: {}", ORACLE_OUTPUT);
            //                             }
            //                             println!(
            //                                 "Found a solution! trace: {}",
            //                                 state
            //                                     .get_execution_result()
            //                                     .new_state
            //                                     .trace
            //                                     .clone()
            //                                     .to_string(state)
            //                             );
            //                             // exit(0);
            //                         } // print_cuda_corpus
            //                     }
            //                     ExecuteCudaInputResult::EXECINTERESTING => {
            //                         let mut gpu_input = cuda_input.clone();
                                    
            //                         // let original_data = gpu_input.get_data_abi().unwrap().get_bytes();
            //                         gpu_input
            //                                 .get_data_abi_mut()
            //                                 .as_mut()
            //                                 .unwrap()
            //                                 .set_bytes(tx_bytes.to_vec());
            //                         gpu_input.set_cuda_input(vec![]); // TODO

            //                         // let after_bytes = gpu_input.get_data_abi().unwrap().get_bytes();
            //                         // println!(
            //                         //     "calldata:=> {:?}\nabi-data:=> {:?}\nafttdata:=> {:?}",
            //                         //     hex::encode(tx_bytes.to_vec()),
            //                         //     hex::encode(original_data.clone()),
            //                         //     hex::encode(after_bytes),
            //                         // );
                                    
            //                         #[cfg(feature = "print_txn_corpus")]
            //                         {
            //                             let tx_trace = state
            //                                 .get_execution_result()
            //                                 .new_state
            //                                 .trace
            //                                 .clone();
            //                             let txn_text = tx_trace.to_string(state);            
            //                             let data = format!(
            //                                 "Reverted? {} \n Txn: {}",
            //                                 state.get_execution_result().reverted,
            //                                 txn_text
            //                             );
            //                             println!("======== New Corpus Item From GPU#{:?} ========", tid);
            //                             println!("{}", data);
            //                             println!("==========================================");
            //                         }
                                    
            //                         // add the cuda-varient to the corpus
            //                         let mut cu_testcase = Testcase::new(gpu_input.clone());
            //                         self.feedback.append_metadata(state, &mut cu_testcase)?;
            //                         let idx = state.corpus_mut().add(cu_testcase)?;
            //                         self.scheduler.on_add(state, idx)?;
            //                         self.on_add_corpus(&gpu_input, unsafe { &JMP_MAP }, idx);
            //                     }
            //                 }
            //             } 
            //             let end_cuda_feedback = current_time();
            //             // println!("feedback in CUDA costs  {:?}", end_cuda_feedback - end_cuda_execute);
            //         }
            //     }

                self.objective.discard_metadata(state, &input)?;
                match self.should_replace(&input, unsafe { &JMP_MAP }) {
                    Some((hash, new_fav_factor, old_testcase_idx)) => {
                        state.corpus_mut().remove(old_testcase_idx)?;

                        let mut testcase = Testcase::new(input.clone());
                        self.feedback.append_metadata(state, &mut testcase)?;
                        let new_testcase_idx = state.corpus_mut().add(testcase)?;
                        self.scheduler.on_add(state, new_testcase_idx)?;
                        self.on_replace_corpus(
                            (hash, new_fav_factor, old_testcase_idx),
                            new_testcase_idx,
                        );

                        Ok((res, Some(new_testcase_idx)))
                    }
                    None => {
                        self.feedback.discard_metadata(state, &input)?;
                        Ok((res, None))
                    }
                }
            }
            // if the input is interesting, we need to add it to the input corpus
            ExecuteInputResult::Corpus => {
                // Not a solution
                self.objective.discard_metadata(state, &input)?;

                // Add the input to the main corpus
                let mut testcase = Testcase::new(input.clone());
                self.feedback.append_metadata(state, &mut testcase)?;
                let idx = state.corpus_mut().add(testcase)?;
                self.scheduler.on_add(state, idx)?;
                self.on_add_corpus(&input, unsafe { &JMP_MAP }, idx);

                // Fire the event for CLI
                if send_events {
                    // TODO set None for fast targets
                    let observers_buf = if manager.configuration() == EventConfig::AlwaysUnique {
                        None
                    } else {
                        Some(manager.serialize_observers(observers)?)
                    };
                    manager.fire(
                        state,
                        Event::NewTestcase {
                            input,
                            observers_buf,
                            exit_kind: exitkind,
                            corpus_size: state.corpus().count(),
                            client_config: manager.configuration(),
                            time: current_time(),
                            executions: *state.executions(),
                        },
                    )?;
                }
                Ok((res, Some(idx)))
            }
            // find the solution
            ExecuteInputResult::Solution => {
                unsafe {
                    println!("Oracle: {}", ORACLE_OUTPUT);
                    if BUGTAGS[0] {
                        println!("Oracle: IntegerBug");
                    }
                    if BUGTAGS[1] {
                        println!("Oracle: Reentrancy");
                    }
                    if BUGTAGS[2] {
                        println!("Oracle: Mishandled Exception");
                    }
                    if BUGTAGS[3] {
                        println!("Oracle: Block State Dependency");
                    }
                    BUGTAGS[0] = false;
                    BUGTAGS[1] = false;
                    BUGTAGS[2] = false;
                    BUGTAGS[3] = false;
                }
                println!(
                    "Found a solution! trace: {}",
                    state
                        .get_execution_result()
                        .new_state
                        .trace
                        .clone()
                        .to_string(state)
                );
                
                if !unsafe { RUN_FOREVER } {
                    exit(0);
                }

                // Not interesting
                self.feedback.discard_metadata(state, &input)?;

                // The input is a solution, add it to the respective corpus
                let mut testcase = Testcase::new(input.clone());
                self.objective.append_metadata(state, &mut testcase)?;
                state.solutions_mut().add(testcase)?;

                if send_events {
                    manager.fire(
                        state,
                        Event::Objective {
                            objective_size: state.solutions().count(),
                        },
                    )?;
                }

                Ok((res, None))
            }
        }
    }

    /// never called!
    fn add_input(
        &mut self,
        state: &mut S,
        executor: &mut E,
        manager: &mut EM,
        input: I,
    ) -> Result<usize, libafl::Error> {
        todo!()
        // start_timer!(state);
        // executor.observers_mut().pre_exec_all(state, &input)?;
        // mark_feature_time!(state, PerfFeature::PreExecObservers);

        // // execute the input
        // start_timer!(state);
        // let exitkind = executor.run_target(self, state, manager, &input)?;
        // mark_feature_time!(state, PerfFeature::TargetExecution);
        // *state.executions_mut() += 1;

        // start_timer!(state);
        // executor
        //     .observers_mut()
        //     .post_exec_all(state, &input, &exitkind)?;
        // mark_feature_time!(state, PerfFeature::PostExecObservers);

        // // add the trace of the new state
        // #[cfg(any(feature = "print_infant_corpus", feature = "print_txn_corpus"))]
        // {
        //     let txn = build_basic_txn(&input, &state.get_execution_result());
        //     state.get_execution_result_mut().new_state.trace.from_idx = Some(input.get_state_idx());
        //     state
        //         .get_execution_result_mut()
        //         .new_state
        //         .trace
        //         .add_txn(txn);
        // }

        // // add the new VM state to infant state corpus if it is interesting
        // state.add_infant_state(
        //     &state.get_execution_result().new_state.clone(),
        //     self.infant_scheduler,
        // );
        // // Debugging prints
        // #[cfg(feature = "print_txn_corpus")]
        // {
        //     unsafe {
        //         DUMP_FILE_COUNT += 1;
        //     }

        //     let tx_trace = state
        //         .get_execution_result()
        //         .new_state
        //         .trace
        //         .clone();
        //     let txn_text = tx_trace.to_string(state);

        //     let txn_text_replayable = tx_trace.to_file_str(state);

        //     let data = format!(
        //         "Reverted? {} \n Txn: {}",
        //         state.get_execution_result().reverted,
        //         txn_text
        //     );
        //     println!("============= New Corpus Item =============");
        //     println!("{}", data);
        //     println!("==========================================");

        //     // write to file
        //     let path = Path::new(self.corpus_path.as_str());
        //     if !path.exists() {
        //         std::fs::create_dir(path).unwrap();
        //     }
        //     let mut file =
        //         File::create(format!("{}/{}", self.corpus_path.as_str(), unsafe { DUMP_FILE_COUNT })).unwrap();
        //     file.write_all(data.as_bytes()).unwrap();

        //     let mut replayable_file =
        //         File::create(format!("{}/{}_replayable", self.corpus_path.as_str(), unsafe { DUMP_FILE_COUNT })).unwrap();
        //     replayable_file.write_all(txn_text_replayable.as_bytes()).unwrap();
        // }
        // self.objective.discard_metadata(state, &input)?;

        // // Add the input to the main corpus
        // let mut testcase = Testcase::new(input.clone());
        // self.feedback.append_metadata(state, &mut testcase)?;
        // let idx = state.corpus_mut().add(testcase)?;
        // self.scheduler.on_add(state, idx)?;
        // self.on_add_corpus(&input, unsafe { &JMP_MAP }, idx);
        // Ok(idx)
    }
}
