use crate::evm::abi::{AEmpty, AUnknown, BoxedABI, BasicVarType};
use crate::evm::input;
use crate::evm::mutation_utils::byte_mutator;
use crate::evm::mutator::AccessPattern;
use crate::evm::types::{EVMAddress, EVMStagedVMState, EVMU256, EVMU512};
use crate::evm::vm::EVMState;
use crate::input::VMInputT;
use crate::state::{HasCaller, HasItyState};
use crate::state_input::StagedVMState;

use libafl::bolts::HasLen;
use libafl::inputs::Input;
use libafl::mutators::MutationResult;
use libafl::prelude::{HasBytesVec, HasMaxSize, HasMetadata, HasRand, Rand, State};
use primitive_types::U512;
use revm_primitives::Env;
use serde::{Deserialize, Deserializer, Serialize};

use bytes::Bytes;
use std::cell::RefCell;
use std::fmt::Debug;
use std::ops::Deref;
use std::rc::Rc;
use std::ptr;
use crate::evm::config::{SEED_SIZE};

/// EVM Input Types
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub enum EVMInputTy {
    /// A normal transaction
    ABI,
    /// A flashloan transaction
    Borrow,
    /// [Depreciated] A liquidation transaction
    Liquidate,
}

/// EVM Input Trait
pub trait EVMInputT {
    /// get the abi types
    fn get_types_vec(&self) -> Vec<u8>;

    /// Get the ABI encoded input
    fn to_bytes(&self) -> Vec<u8>;

    /// Get revm environment (block, timestamp, etc.)
    fn get_vm_env(&self) -> &Env;

    /// Get revm environment (block, timestamp, etc.) mutably
    fn get_vm_env_mut(&mut self) -> &mut Env;

    /// Get the access pattern of the input, used by the mutator to determine what to mutate
    fn get_access_pattern(&self) -> &Rc<RefCell<AccessPattern>>;

    /// Get the transaction value in wei
    fn get_txn_value(&self) -> Option<EVMU256>;

    /// Set the transaction value in wei
    fn set_txn_value(&mut self, v: EVMU256);

    /// Get input type
    #[cfg(feature = "flashloan_v2")]
    fn get_input_type(&self) -> EVMInputTy;

    /// Get additional random bytes for mutator
    fn get_randomness(&self) -> Vec<u8>;

    /// Set additional random bytes for mutator
    fn set_randomness(&mut self, v: Vec<u8>);

    /// Get the percentage of the token amount in all callers' account to liquidate
    #[cfg(feature = "flashloan_v2")]
    fn get_liquidation_percent(&self) -> u8;

    /// Set the percentage of the token amount in all callers' account to liquidate
    #[cfg(feature = "flashloan_v2")]
    fn set_liquidation_percent(&mut self, v: u8);

    fn get_repeat(&self) -> usize;

    // fn get_cuda_input(&self) -> Vec<u8>;

    // fn set_cuda_input(&mut self, v: Vec<u8>);

    fn get_evm_addr(&self) -> EVMAddress;

    fn get_calldata(&self) -> Vec<u8>;

    fn cu_load_evm_env(&self);

    fn cu_load_input(&self, tid: u32);

    fn cu_load_storage(&self, tid: u32);

    fn get_distance(&self) -> usize;
    fn set_distance(&mut self, distance:usize);

    fn set_cuda_input(&mut self, status:bool);

}


/// EVM Input
#[derive(Serialize, Deserialize, Clone)]
pub struct EVMInput {
    /// Input type
    #[cfg(feature = "flashloan_v2")]
    pub input_type: EVMInputTy,

    /// Caller address
    pub caller: EVMAddress,

    /// Contract address
    pub contract: EVMAddress,

    /// Input data in ABI format
    pub data: Option<BoxedABI>,

    /// Staged VM state
    pub sstate: StagedVMState<EVMAddress, EVMAddress, EVMState>,

    /// Staged VM state index in the corpus
    pub sstate_idx: usize,

    /// Transaction value in wei
    pub txn_value: Option<EVMU256>,

    /// Whether to resume execution from the last control leak
    pub step: bool,

    /// Environment (block, timestamp, etc.)
    pub env: Env,

    /// Access pattern
    pub access_pattern: Rc<RefCell<AccessPattern>>,

    /// Percentage of the token amount in all callers' account to liquidate
    #[cfg(feature = "flashloan_v2")]
    pub liquidation_percent: u8,

    /// If ABI is empty, use direct data, which is the raw input data
    pub direct_data: Bytes,

    /// Additional random bytes for mutator
    pub randomness: Vec<u8>,

    /// Execute the transaction multiple times
    pub repeat: usize,

    /// cuda input
    pub cu_data: Vec<u8>,

    pub is_cuda: bool,
    pub branch_distance: usize,
}

impl HasLen for EVMInput {
    /// Get the length of the ABI encoded input
    fn len(&self) -> usize {
        match self.data {
            Some(ref d) => d.get_bytes().len(),
            None => 0,
        }
    }
}

impl std::fmt::Debug for EVMInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VMInput")
            .field("caller", &self.caller)
            .field("contract", &self.contract)
            // .field("data", &self.data)
            .field("state", &self.sstate)
            .field("state_idx", &self.sstate_idx)
            .field("txn_value", &self.txn_value)
            .field("step", &self.step)
            .finish()
    }
}

impl EVMInputT for EVMInput {
    fn to_bytes(&self) -> Vec<u8> {
        match self.data {
            Some(ref d) => d.get_bytes(),
            None => vec![],
        }
    }

    fn get_types_vec(&self) -> Vec<u8> {
        match self.data {
            Some(ref d) => {
                let t = d.get_basic_types();
                
                let mut r: Vec<u8> = Vec::new();
                for i in 0..t.len() {
                    r.push(t[i] as u8);
                }
                r
            },
            None => vec![],
        }
    }

    fn get_vm_env_mut(&mut self) -> &mut Env {
        &mut self.env
    }

    fn get_vm_env(&self) -> &Env {
        &self.env
    }

    fn get_access_pattern(&self) -> &Rc<RefCell<AccessPattern>> {
        &self.access_pattern
    }

    fn get_txn_value(&self) -> Option<EVMU256> {
        self.txn_value
    }

    fn set_txn_value(&mut self, v: EVMU256) {
        self.txn_value = Some(v);
    }

    #[cfg(feature = "flashloan_v2")]
    fn get_input_type(&self) -> EVMInputTy {
        self.input_type.clone()
    }

    fn get_randomness(&self) -> Vec<u8> {
        self.randomness.clone()
    }

    fn set_randomness(&mut self, v: Vec<u8>) {
        self.randomness = v;
    }

    #[cfg(feature = "flashloan_v2")]
    fn get_liquidation_percent(&self) -> u8 {
        self.liquidation_percent
    }

    #[cfg(feature = "flashloan_v2")]
    fn set_liquidation_percent(&mut self, v: u8) {
        self.liquidation_percent = v;
    }

    fn get_repeat(&self) -> usize {
        self.repeat
    }

    // fn get_cuda_input(&self) -> Vec<u8> {
    //     self.cu_data.clone()
    // }

    // fn set_cuda_input(&mut self, v: Vec<u8>) {
    //     self.cu_data = v;
    // }
    fn get_evm_addr(&self) -> EVMAddress {
        self.contract.clone()
    }
    fn get_calldata(&self) -> Vec<u8> {
        match self.data {
            None => self.direct_data.to_vec(),
            Some(ref abi) => abi.get_bytes(), // function hash + encoded args
        }
    }

    fn cu_load_evm_env(&self) {
        let block = &self.env.block;
        let timestamp: [u8; 32] = block.timestamp.to_le_bytes();
        let blocknum: [u8; 32] = block.number.to_le_bytes();
        // println!("timestamp = {:?}", timestamp);
        let mut to: [u8; 20]  = self.get_contract().to_fixed_bytes();
        to.reverse();
   

        #[link(name = "runner")]
        extern "C" {
            fn setEVMEnv(To: *const u8, Timestamp: *const u8, Blocknum: *const u8) -> bool;
        }
        unsafe {
            setEVMEnv(to.as_ptr(),
                      timestamp.as_ptr(), 
                      blocknum.as_ptr());
        }
    }

    fn cu_load_input(&self, tid: u32) {
        #[link(name = "runner")]
        extern "C" {
            fn cuLoadSeed(caller_ptr: *const u8, value_ptr: *const u8, data_ptr: *const u8, data_size: u32, state_idx: u32, thread: u32);
            fn cuGetStoragePos(s_idx: u32) -> u32;
        }
        let mut caller =  self.get_caller().to_fixed_bytes();
        caller.reverse();
        let callvalue: [u8; 32] = self.get_txn_value().unwrap_or(EVMU256::ZERO).to_le_bytes();

        let calldata = self.get_calldata();
        
        let calldatasize = calldata.len();

        if 68 + calldatasize > SEED_SIZE {
            println!("[-] Increate the SEED_SIZE. calldatasize({:?}) > {:?}.", 68 + calldatasize, SEED_SIZE);
        }
        // println!("state ectracting idx = {:?}",  self.get_state_idx());

        // let state_idx;
        // #[cfg(feature = "cuda_snapshot_storage")] 
        // {   
        //     state_idx = self.get_state_idx() as u32
        //     // println!("state idx = {:?}", state_idx);
        // }
        // #[cfg(not(feature = "cuda_snapshot_storage"))]
        // {   
        //     state_idx = tid;
        //     // load historical storage
        // }
        // self.cu_load_storage(state_idx);
        // self.cu_load_storage(tid);
        
        unsafe {
            cuLoadSeed(
                caller.as_ptr(), 
                callvalue.as_ptr(), 
                calldata.as_ptr(), 
                calldatasize as u32, 
                0,
                tid,
            );
        }
    }

    fn cu_load_storage(&self, state_id: u32) {
        #[link(name = "runner")]
        extern "C" {
            fn cuLoadStorage(src: *const u8, slotCnt: u32, state_id: u32);
        }
        // load initial storage one by one (heavy mode)
        if let Some(storage) = self.get_state().get(&self.get_contract()) {
            let mut bytes = Vec::new();
            // println!("storage content before executing input=> {:?}", storage);
            for (key, value) in storage {
                // for (key, value) in storage {
                //     println!("{:#x}: {:#x}", key, value);
                // }
                let slot = [key.as_le_bytes(), value.as_le_bytes()].concat();
                bytes.extend(slot);
            }
            unsafe{ cuLoadStorage(bytes.as_ptr(), storage.len() as u32, state_id as u32); }
        } else {
            unsafe{ cuLoadStorage(ptr::null(), 0, state_id as u32); }
        }
    }

    fn get_distance(&self) -> usize {
        self.branch_distance
    }

    fn set_distance(&mut self, distance:usize) {
        self.branch_distance = distance;
    }

    fn set_cuda_input(&mut self, status:bool) {
        self.is_cuda = status;
    }
}


///
macro_rules! impl_env_mutator_u256 {
    ($item: ident, $loc: ident) => {
        pub fn $item<S>(input: &mut EVMInput, state_: &mut S) -> MutationResult
        where
            S: State + HasCaller<EVMAddress> + HasRand + HasMetadata,
        {
            let vm_slots = if let Some(s) = input.get_state().get(&input.get_contract()) {
                Some(s.clone())
            } else {
                None
            };
            let mut input_by: [u8; 32] = input.get_vm_env().$loc.$item.to_be_bytes();
            let mut input_vec = input_by.to_vec();
            let mut wrapper = MutatorInput::new(&mut input_vec);
            let res = byte_mutator(state_, &mut wrapper, vm_slots);
            if res == MutationResult::Skipped {
                return res;
            }
            input.get_vm_env_mut().$loc.$item = EVMU256::try_from_be_slice(&input_vec.as_slice()).unwrap();
            res
        }
    };
}

macro_rules! impl_env_mutator_h160 {
    ($item: ident, $loc: ident) => {
        pub fn $item<S>(input: &mut EVMInput, state_: &mut S) -> MutationResult
        where
            S: State + HasCaller<EVMAddress> + HasRand,
        {
            let addr = state_.get_rand_caller();
            if addr == input.get_caller() {
                return MutationResult::Skipped;
            } else {
                input.get_vm_env_mut().$loc.$item = addr;
                MutationResult::Mutated
            }
        }
    };
}

// Wrapper for EVMU256 so that it represents a mutable Input in LibAFL
#[derive(Serialize)]
struct MutatorInput<'a> {
    #[serde(skip_serializing)]
    pub val_vec: &'a mut Vec<u8>,
}

impl<'a, 'de> Deserialize<'de> for MutatorInput<'a> {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        unreachable!()
    }
}

impl<'a> Clone for MutatorInput<'a> {
    fn clone(&self) -> Self {
        unreachable!()
    }
}

impl<'a> Debug for MutatorInput<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MutatorInput")
            .field("val_vec", &self.val_vec)
            .finish()
    }
}

impl<'a> MutatorInput<'a> {
    pub fn new(val_vec: &'a mut Vec<u8>) -> Self {
        MutatorInput { val_vec }
    }
}

impl<'a> Input for MutatorInput<'a> {
    fn generate_name(&self, idx: usize) -> String {
        format!("{}_{:?}", idx, self.val_vec)
    }
}

impl<'a> HasBytesVec for MutatorInput<'a> {
    fn bytes(&self) -> &[u8] {
        self.val_vec
    }

    fn bytes_mut(&mut self) -> &mut Vec<u8> {
        self.val_vec
    }
}

impl EVMInput {
    impl_env_mutator_u256!(basefee, block);
    impl_env_mutator_u256!(timestamp, block);
    impl_env_mutator_h160!(coinbase, block);
    impl_env_mutator_u256!(gas_limit, block);
    impl_env_mutator_u256!(number, block);
    impl_env_mutator_u256!(chain_id, cfg);

    pub fn prevrandao<S>(_input: &mut EVMInput, _state_: &mut S) -> MutationResult
    where
        S: State + HasCaller<EVMAddress> + HasRand + HasMetadata,
    {
        // not supported yet
        // unreachable!();
        return MutationResult::Skipped;
    }

    pub fn gas_price<S>(_input: &mut EVMInput, _state_: &mut S) -> MutationResult
    where
        S: State + HasCaller<EVMAddress> + HasRand + HasMetadata,
    {
        // not supported yet
        // unreachable!();
        return MutationResult::Skipped;
    }

    pub fn balance<S>(_input: &mut EVMInput, _state_: &mut S) -> MutationResult
    where
        S: State + HasCaller<EVMAddress> + HasRand + HasMetadata,
    {
        // not supported yet
        // unreachable!();
        return MutationResult::Skipped;
    }

    pub fn caller<S>(input: &mut EVMInput, state_: &mut S) -> MutationResult
    where
        S: State + HasCaller<EVMAddress> + HasRand + HasMetadata,
    {
        let caller = state_.get_rand_caller();
        if caller == input.get_caller() {
            return MutationResult::Skipped;
        } else {
            input.set_caller(caller);
            MutationResult::Mutated
        }
    }

    pub fn call_value<S>(input: &mut EVMInput, state_: &mut S) -> MutationResult
    where
        S: State + HasCaller<EVMAddress> + HasRand + HasMetadata,
    {
        let vm_slots = if let Some(s) = input.get_state().get(&input.get_contract()) {
            Some(s.clone())
        } else {
            None
        };
        let mut input_by: [u8; 32] = input
            .get_txn_value()
            .unwrap_or(EVMU256::ZERO)
            .to_be_bytes();
        let mut input_vec = input_by.to_vec();
        let mut wrapper = MutatorInput::new(&mut input_vec);
        let res = byte_mutator(state_, &mut wrapper, vm_slots);
        if res == MutationResult::Skipped {
            return res;
        }
        // make set first 16 bytes to 0
        for i in 0..16 {
            input_vec[i] = 0;
        }
        input.set_txn_value(EVMU256::try_from_be_slice(input_vec.as_slice()).unwrap());
        res
    }

    pub fn mutate_env_with_access_pattern<S>(&mut self, state: &mut S) -> MutationResult
    where
        S: State + HasCaller<EVMAddress> + HasRand + HasMetadata,
    {
        let ap = self.get_access_pattern().deref().borrow().clone();
        let mut mutators = vec![];
        macro_rules! add_mutator {
            ($item: ident) => {
                if ap.$item {
                    mutators
                        .push(&EVMInput::$item as &dyn Fn(&mut EVMInput, &mut S) -> MutationResult);
                }
            };

            ($item: ident, $cond: expr) => {
                if $cond {
                    mutators
                        .push(&EVMInput::$item as &dyn Fn(&mut EVMInput, &mut S) -> MutationResult);
                }
            };
        }
        add_mutator!(caller);
        add_mutator!(balance, ap.balance.len() > 0);
        if ap.call_value || self.get_txn_value().is_some() {
            mutators
                .push(&EVMInput::call_value as &dyn Fn(&mut EVMInput, &mut S) -> MutationResult);
        }
        add_mutator!(gas_price);
        add_mutator!(basefee);
        add_mutator!(timestamp);
        add_mutator!(coinbase);
        add_mutator!(gas_limit);
        add_mutator!(number);
        add_mutator!(chain_id);
        add_mutator!(prevrandao);

        if mutators.len() == 0 {
            return MutationResult::Skipped;
        }

        let mutator = mutators[state.rand_mut().below(mutators.len() as u64) as usize];
        mutator(self, state)
    }
}

impl VMInputT<EVMState, EVMAddress, EVMAddress> for EVMInput {
    fn mutate<S>(&mut self, state: &mut S) -> MutationResult
    where
        S: State
            + HasRand
            + HasMaxSize
            + HasItyState<EVMAddress, EVMAddress, EVMState>
            + HasCaller<EVMAddress>
            + HasMetadata,
    {
        if !self.is_cuda && (state.rand_mut().next() % 100 > 87 || self.data.is_none()) {
            return self.mutate_env_with_access_pattern(state);
        }
        let vm_slots = if let Some(s) = self.get_state().get(&self.get_contract()) {
            Some(s.clone())
        } else {
            None
        };
        match self.data {
            Some(ref mut data) => {
                // println!("type before => {:?}", data.get_type());
                let a = data.mutate_with_vm_slots(state, vm_slots);
                // println!("type=> after {:?}", data.get_type());
                a
            },
            None => MutationResult::Skipped,
        }
    }

    fn get_caller_mut(&mut self) -> &mut EVMAddress {
        &mut self.caller
    }

    fn get_caller(&self) -> EVMAddress {
        self.caller.clone()
    }

    fn set_caller(&mut self, caller: EVMAddress) {
        self.caller = caller;
    }

    fn get_contract(&self) -> EVMAddress {
        self.contract.clone()
    }

    fn set_evm_env(&self) -> &Env {
        let block = &self.env.block;
        let timestamp: [u8; 32] = block.timestamp.to_le_bytes();
        let blocknum: [u8; 32] = block.number.to_le_bytes();

        let to: [u8; 20]  = self.get_contract().to_fixed_bytes();
        let caller: [u8; 20] = self.get_caller().to_fixed_bytes();
        let callvalue: [u8; 32] = self.get_txn_value().unwrap_or(EVMU256::ZERO).to_le_bytes();
   

        #[link(name = "runner")]
        extern "C" {
            fn setEVMEnv(From: *const u8, To: *const u8, Timestamp: *const u8, Blocknum: *const u8) -> bool;
        }
        unsafe {
            setEVMEnv(caller.as_ptr(),
                      to.as_ptr(),
                      timestamp.as_ptr(), 
                      blocknum.as_ptr());
        }

        &self.env
    }

    fn get_evm_contract(&self) -> EVMAddress {
        self.contract.clone()
    }

    fn get_state(&self) -> &EVMState {
        &self.sstate.state
    }

    fn get_state_mut(&mut self) -> &mut EVMState {
        &mut self.sstate.state
    }

    fn set_staged_state(&mut self, state: EVMStagedVMState, idx: usize) {
        self.sstate = state;
        self.sstate_idx = idx;
    }

    fn get_state_idx(&self) -> usize {
        self.sstate_idx
    }

    fn get_staged_state(&self) -> &EVMStagedVMState {
        &self.sstate
    }

    fn set_as_post_exec(&mut self, out_size: usize) {
        self.data = Some(BoxedABI::new(Box::new(AUnknown {
            concrete: BoxedABI::new(Box::new(AEmpty {})),
            size: out_size,
        })));
    }

    fn is_step(&self) -> bool {
        self.step
    }

    fn set_step(&mut self, gate: bool) {
        self.txn_value = None;
        self.step = gate;
    }

    #[cfg(feature = "flashloan_v2")]
    fn pretty_txn(&self) -> Option<String> {
        let liq = self.liquidation_percent;
        match self.data {
            Some(ref d) => Some(format!(
                "{} with {:?} ETH ({}), liq percent: {}",
                d.to_string(),
                self.txn_value,
                hex::encode(d.get_bytes()),
                liq
            )),
            None => match self.input_type {
                EVMInputTy::ABI => Some(format!(
                    "ABI with {:?} ETH, liq percent: {}",
                    self.txn_value, liq
                )),
                EVMInputTy::Borrow => Some(format!(
                    "Borrow with {:?} ETH, liq percent: {}",
                    self.txn_value, liq
                )),
                EVMInputTy::Liquidate => None,
            },
        }
    }

    #[cfg(not(feature = "flashloan_v2"))]
    fn pretty_txn(&self) -> Option<String> {
        match self.data {
            Some(ref d) => Some(format!(
                "{} with {:?} ETH ({})",
                d.to_string(),
                self.txn_value,
                hex::encode(d.get_bytes())
            )),
            None => Some(format!("ABI with {:?} ETH", self.txn_value)),
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn fav_factor(&self) -> f64 {
        if self.sstate.state.flashloan_data.earned > self.sstate.state.flashloan_data.owed {
            return f64::MAX;
        }
        let owed_amount =
            self.sstate.state.flashloan_data.owed - self.sstate.state.flashloan_data.earned;

        if owed_amount == EVMU512::ZERO {
            return f64::MAX;
        }

        // hacky convert from U512 -> f64
        let mut res = 0.0;
        for idx in 0..8 {
            res += owed_amount.as_limbs()[idx] as f64 * (u64::MAX as f64).powi(idx as i32 - 4);
        }
        res
    }

    #[cfg(feature = "evm")]
    fn get_data_abi(&self) -> Option<BoxedABI> {
        self.data.clone()
    }

    fn get_direct_data(&self) -> Vec<u8> {
        self.direct_data.to_vec()
    }

    #[cfg(feature = "evm")]
    fn get_data_abi_mut(&mut self) -> &mut Option<BoxedABI> {
        &mut self.data
    }

    #[cfg(feature = "evm")]
    fn get_txn_value_temp(&self) -> Option<EVMU256> {
        self.txn_value
    }

    #[cfg(feature = "evm")]
    fn get_cuda_input(&self) -> Vec<u8> {
        self.cu_data.clone()
    }

    // #[cfg(feature = "evm")]
    // fn set_cuda_input(&mut self) {
    //     self.is_cuda = true;
    // }

    #[cfg(feature = "evm")]
    fn get_distance(&self) -> usize {
        self.branch_distance
    }

    #[cfg(feature = "evm")]
    fn set_distance(&mut self, distance:usize) {
        self.branch_distance = distance;
    }

}

impl Input for EVMInput {
    fn generate_name(&self, idx: usize) -> String {
        format!("input-{:06}.bin", idx)
    }

    // fn to_file<P>(&self, path: P) -> Result<(), libafl::Error>
    //     where
    //         P: AsRef<std::path::Path>, {

    // }

    fn wrapped_as_testcase(&mut self) {
        // todo!()
    }
}
