pub mod util;
pub mod output;
pub mod analyze;
pub mod resolve;
pub mod constants;
pub mod precompile;
pub mod postprocess;

use crate::decompile::util::*;
use crate::decompile::output::*;
use crate::decompile::resolve::*;

use std::collections::HashMap;
use std::env;
use std::fs;
use std::time::Duration;
use indicatif::ProgressBar;

use clap::{AppSettings, Parser};
use ethers::{
    core::types::{Address},
    providers::{Middleware, Provider, Http},
};
use heimdall_common::{
    ether::evm::{
        disassemble::{
            DisassemblerArgs,
            disassemble
        },
        vm::VM
    },
    ether::signatures::*,
    consts::{ ADDRESS_REGEX, BYTECODE_REGEX },
    io::{ logging::* },
};

#[derive(Debug, Clone, Parser)]
#[clap(about = "Decompile EVM bytecode to Solidity",
       after_help = "For more information, read the wiki: https://jbecker.dev/r/heimdall-rs/wiki",
       global_setting = AppSettings::DeriveDisplayOrder, 
       override_usage = "heimdall decompile <TARGET> [OPTIONS]")]
pub struct DecompilerArgs {
    
    /// The target to decompile, either a file, bytecode, contract address, or ENS name.
    #[clap(required=true)]
    pub target: String,

    /// Set the output verbosity level, 1 - 5.
    #[clap(flatten)]
    pub verbose: clap_verbosity_flag::Verbosity,
    
    /// The output directory to write the decompiled files to
    #[clap(long="output", short, default_value = "", hide_default_value = true)]
    pub output: String,

    /// The RPC provider to use for fetching target bytecode.
    #[clap(long="rpc-url", short, default_value = "", hide_default_value = true)]
    pub rpc_url: String,

    /// When prompted, always select the default value.
    #[clap(long, short)]
    pub default: bool,

    /// Whether to skip resolving function selectors.
    #[clap(long="skip-resolving")]
    pub skip_resolving: bool,

}


pub fn decompile_with_bytecode(contract_bytecode: String, output_dir: String) -> Vec<ABIStructure>{
    use std::time::Instant;
    let now = Instant::now();

    let skip_resolving = true;

    let default_val = true;

    let (logger, mut trace)= Logger::new("TRACE");

    let decompile_call = trace.add_call(
        0, line!(),
        "heimdall".to_string(),
        "decompile".to_string(),
        vec!["target".to_string()],
        "()".to_string()
    );

    // disassemble the bytecode
    let disassembled_bytecode = disassemble(contract_bytecode.clone(), output_dir.clone());
    trace.add_call(
        decompile_call,
        line!(),
        "heimdall".to_string(),
        "disassemble".to_string(),
        vec![format!("{} bytes", contract_bytecode.len()/2usize)],
        "()".to_string()
    );
    
    // perform versioning and compiler heuristics
    let (compiler, version) = detect_compiler(contract_bytecode.clone());
    trace.add_call(
        decompile_call, 
        line!(), 
        "heimdall".to_string(), 
        "detect_compiler".to_string(),
        vec![format!("{} bytes", contract_bytecode.len()/2usize)], 
        format!("({}, {})", compiler, version)
    );

    if compiler == "solc" {
        logger.debug(&format!("detected compiler {} {}.", compiler, version));
    }
    else {
        logger.warn(&format!("detected compiler {} {} is not supported by heimdall.", compiler, version));
    }

    // create a new EVM instance
    let evm = VM::new(
        contract_bytecode.clone(),
        String::from("0x"),
        String::from("0x6865696d64616c6c000000000061646472657373"),
        String::from("0x6865696d64616c6c0000000000006f726967696e"),
        String::from("0x6865696d64616c6c00000000000063616c6c6572"),
        0,
        u128::max_value(),
    );
    let mut shortened_target = contract_bytecode.clone();
    if shortened_target.len() > 66 {
        shortened_target = shortened_target.chars().take(66).collect::<String>() + "..." + &shortened_target.chars().skip(shortened_target.len() - 16).collect::<String>();
    }
    let vm_trace = trace.add_creation(decompile_call, line!(), "contract".to_string(), shortened_target, (contract_bytecode.len()/2usize).try_into().unwrap());

    // find and resolve all selectors in the bytecode
    let selectors = find_function_selectors(&evm.clone(), disassembled_bytecode);

    let mut resolved_selectors = HashMap::new();
    if !skip_resolving {
        resolved_selectors = resolve_function_selectors(selectors.clone(), &logger);
        logger.info(&format!("resolved {} possible functions from {} detected selectors.", resolved_selectors.len(), selectors.len()).to_string());
    }
    else {
        logger.info(&format!("found {} function selectors.", selectors.len()).to_string());
    }

    let decompilation_progress = ProgressBar::new_spinner();
    decompilation_progress.enable_steady_tick(Duration::from_millis(100));
    decompilation_progress.set_style(logger.info_spinner());

    // perform EVM analysis
    let mut analyzed_functions = Vec::new();
    for selector in selectors.clone() {
        decompilation_progress.set_message(format!("executing '0x{}'", selector));
        
        let func_analysis_trace = trace.add_call(
            vm_trace, 
            line!(), 
            "heimdall".to_string(), 
            "analyze".to_string(), 
            vec![format!("0x{}", selector)], 
            "()".to_string()
        );

        // get the function's entry point
        let function_entry_point = resolve_entry_point(&evm.clone(), selector.clone());
        trace.add_info(
            func_analysis_trace, 
            function_entry_point.try_into().unwrap(), 
            format!("discovered entry point: {}", function_entry_point).to_string()
        );

        if function_entry_point == 0 {
            trace.add_error(
                func_analysis_trace,
                line!(), 
                "selector flagged as false-positive.".to_string()
            );
            continue;
        }

        // get a map of possible jump destinations
        let (map, jumpdests) = map_selector(&evm.clone(), &trace, func_analysis_trace, selector.clone(), function_entry_point);
        trace.add_debug(
            func_analysis_trace,
            function_entry_point.try_into().unwrap(),
            format!("execution tree {}",
            
            match jumpdests.len() {
                0 => "appears to be linear".to_string(),
                _ => format!("has {} branches", jumpdests.len()+1)
            }
            ).to_string()
        );
        
        decompilation_progress.set_message(format!("analyzing '0x{}'", selector));

        // solidify the execution tree
        let mut analyzed_function = map.analyze(
            Function {
                selector: selector.clone(),
                entry_point: function_entry_point.clone(),
                arguments: HashMap::new(),
                storage: HashMap::new(),
                memory: HashMap::new(),
                returns: None,
                logic: Vec::new(),
                events: HashMap::new(),
                errors: HashMap::new(),
                resolved_function: None,
                pure: true,
                view: true,
                payable: false,
            },
            &mut trace,
            func_analysis_trace,
        );

        let argument_count = analyzed_function.arguments.len();

        if argument_count != 0 {
            let parameter_trace_parent = trace.add_debug(
                func_analysis_trace,
                line!(),
                format!("discovered and analyzed {} function parameters", argument_count).to_string()
            );

            let mut parameter_vec = Vec::new();
            for (_, value) in analyzed_function.arguments.clone() {
                parameter_vec.push(value);
            }
            parameter_vec.sort_by(|a, b| a.0.slot.cmp(&b.0.slot));


            for (frame, _) in parameter_vec {
                trace.add_message(
                    parameter_trace_parent,
                    line!(),
                    vec![
                        format!(
                            "parameter {} {} {} bytes. {}",
                            frame.slot,
                            if frame.mask_size == 32 { "has size of" } else { "is masked to" },
                            frame.mask_size,
                            if frame.heuristics.len() > 0 {
                                format!("heuristics suggest param used as '{}'", frame.heuristics[0])
                            } else {
                                "".to_string()
                            }
                        ).to_string()
                    ]
                );
            }
        }

        if !skip_resolving {

            let resolved_functions = match resolved_selectors.get(&selector) {
                Some(func) => func.clone(),
                None => {
                    trace.add_error(
                        func_analysis_trace,
                        line!(),
                        "failed to resolve function.".to_string()
                    );
                    continue;
                }
            };

            let matched_resolved_functions = match_parameters(resolved_functions, &analyzed_function);
            
            trace.br(func_analysis_trace);
            if matched_resolved_functions.len() == 0 {
                trace.add_warn(
                    func_analysis_trace,
                    line!(),
                    "no resolved signatures matched this function's parameters".to_string()
                );
            }
            else {
                
                let mut selected_function_index: u8 = 0;
                if matched_resolved_functions.len() > 1 {
                    decompilation_progress.suspend(|| {
                        selected_function_index = logger.option(
                            "warn", "multiple possible matches found. select an option below",
                            matched_resolved_functions.iter()
                            .map(|x| x.signature.clone()).collect(),
                            Some(*&(matched_resolved_functions.len()-1) as u8),
                            default_val
                        );
                    });
                }

                let selected_match = match matched_resolved_functions.get(selected_function_index as usize) {
                    Some(selected_match) => selected_match,
                    None => {
                        logger.error("invalid selection.");
                        std::process::exit(1)
                    }
                };

                analyzed_function.resolved_function = Some(selected_match.clone());

                let match_trace = trace.add_info(
                    func_analysis_trace,
                    line!(),
                    format!(
                        "{} resolved signature{} matched this function's parameters",
                        matched_resolved_functions.len(),
                        if matched_resolved_functions.len() > 1 { "s" } else { "" }
                    ).to_string()
                );

                for resolved_function in matched_resolved_functions {
                    trace.add_message(
                        match_trace,
                        line!(),
                        vec![resolved_function.signature]
                    );
                }

            }
        }


        if !skip_resolving {

            // resolve custom error signatures
            let mut resolved_counter = 0;
            for (error_selector, _) in analyzed_function.errors.clone() {
                decompilation_progress.set_message(format!("resolving error 0x{}", &error_selector));
                let resolved_error_selectors = resolve_error_signature(&error_selector);

                // only continue if we have matches
                match resolved_error_selectors {
                    Some(resolved_error_selectors) => {

                        let mut selected_error_index: u8 = 0;
                        if resolved_error_selectors.len() > 1 {
                            decompilation_progress.suspend(|| {
                                selected_error_index = logger.option(
                                    "warn", "multiple possible matches found. select an option below",
                                    resolved_error_selectors.iter()
                                    .map(|x| x.signature.clone()).collect(),
                                    Some(*&(resolved_error_selectors.len()-1) as u8),
                                    default_val
                                );
                            });
                        }
        
                        let selected_match = match resolved_error_selectors.get(selected_error_index as usize) {
                            Some(selected_match) => selected_match,
                            None => {
                                logger.error("invalid selection.");
                                std::process::exit(1)
                            }
                        };
                        
                        resolved_counter += 1;
                        analyzed_function.errors.insert(error_selector, Some(selected_match.clone()));
                    },
                    None => {}
                }
               
            }

            if resolved_counter > 0 {
                trace.br(func_analysis_trace);
                trace.add_info(
                    func_analysis_trace,
                    line!(),
                    format!("resolved {} error signatures from {} selectors.", resolved_counter, analyzed_function.errors.len()).to_string()
                );
            }

            // resolve custom event signatures
            resolved_counter = 0;
            for (event_selector, (_, raw_event)) in analyzed_function.events.clone() {
                decompilation_progress.set_message(format!("resolving event 0x{}", &event_selector.get(0..8).unwrap().to_string()));
                let resolved_event_selectors = resolve_event_signature(&event_selector.get(0..64).unwrap().to_string());

                // only continue if we have matches
                match resolved_event_selectors {
                    Some(resolved_event_selectors) => {

                        let mut selected_event_index: u8 = 0;
                        if resolved_event_selectors.len() > 1 {
                            decompilation_progress.suspend(|| {
                                selected_event_index = logger.option(
                                    "warn", "multiple possible matches found. select an option below",
                                    resolved_event_selectors.iter()
                                    .map(|x| x.signature.clone()).collect(),
                                    Some(*&(resolved_event_selectors.len()-1) as u8),
                                    default_val
                                );
                            });
                        }
        
                        let selected_match = match resolved_event_selectors.get(selected_event_index as usize) {
                            Some(selected_match) => selected_match,
                            None => {
                                logger.error("invalid selection.");
                                std::process::exit(1)
                            }
                        };

                        resolved_counter += 1;
                        analyzed_function.events.insert(event_selector, (Some(selected_match.clone()), raw_event));
                    },
                    None => {}
                }
               
            }

            if resolved_counter > 0 {
                trace.add_info(
                    func_analysis_trace,
                    line!(),
                    format!("resolved {} event signatures from {} selectors.", resolved_counter, analyzed_function.events.len()).to_string()
                );
            }
        }

        analyzed_functions.push(analyzed_function.clone());


    }
    decompilation_progress.finish_and_clear();
    logger.info("symbolic execution completed.");
    logger.info("building decompilation output.");
    logger.debug(&format!("decompilation completed in {:?}.", now.elapsed()).to_string());

    // create the decompiled source output
    build_output(
        output_dir,
        analyzed_functions,
        &logger,
        &mut trace,
        decompile_call,
    )

    // trace.display();
}
