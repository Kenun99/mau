/// Configuration for the EVM fuzzer
use crate::evm::contract_utils::ContractInfo;
use crate::evm::onchain::endpoints::{OnChainConfig, PriceOracle};

use crate::evm::oracles::erc20::IERC20OracleFlashloan;
use crate::oracle::{Oracle, Producer};
use std::cell::RefCell;
use std::rc::Rc;

pub enum FuzzerTypes {
    CMP,
    DATAFLOW,
    BASIC,
}

pub enum StorageFetchingMode {
    Dump,
    All,
    OneByOne,
}

impl StorageFetchingMode {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "dump" => Some(StorageFetchingMode::Dump),
            "all" => Some(StorageFetchingMode::All),
            "onebyone" => Some(StorageFetchingMode::OneByOne),
            _ => None,
        }
    }
}

impl FuzzerTypes {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "cmp" => Ok(FuzzerTypes::CMP),
            "dataflow" => Ok(FuzzerTypes::DATAFLOW),
            "basic" => Ok(FuzzerTypes::BASIC),
            _ => Err(format!("Unknown fuzzer type: {}", s)),
        }
    }
}

pub struct Config<VS, Addr, Code, By, Loc, SlotTy, Out, I, S> {
    pub onchain: Option<OnChainConfig>,
    pub onchain_storage_fetching: Option<StorageFetchingMode>,
    pub flashloan: bool,
    pub concolic: bool,
    pub fuzzer_type: FuzzerTypes,
    pub contract_info: Vec<ContractInfo>,
    pub oracle: Vec<Rc<RefCell<dyn Oracle<VS, Addr, Code, By, Loc, SlotTy, Out, I, S>>>>,
    pub producers: Vec<Rc<RefCell<dyn Producer<VS, Addr, Code, By, Loc, SlotTy, Out, I, S>>>>,
    pub price_oracle: Box<dyn PriceOracle>,
    pub replay_file: Option<String>,
    pub flashloan_oracle: Rc<RefCell<IERC20OracleFlashloan>>,
    pub corpus_path: String,
    pub ptx_path: String,
    pub gpu_dev: i32,
    pub run_forever: bool,
    pub cov_path: String,
}


/* (ALIGN_UP(CALLDATA_SIZE, 8))  in 64 bits*/
pub const SEED_SIZE: usize = 2048;

pub const NJOBS: u32 =  1024;

pub static mut RUN_FOREVER: bool = false;

pub static mut GPU_ENABLE: bool = false;

pub static mut DUMP_CORPUS: bool = false;

pub const STATS_CPU_DEFAULT: u64 = 300; // 5min

pub const GPU_BALANCE_PERCENT: u64 = 10; 