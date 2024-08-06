//! # CKB Transaction Cobuild Helper Library
//! This library is designed to assist developers in integrating cobuild support
//! into their scripts with ease.
//!
//! ### For Lock Script
//! Begin by implementing the `Callback` trait for your verifier:
//! ```
//! impl Callback for Verifier {
//!     fn invoke(
//!         &self,
//!         seal: &[u8],
//!         signing_message_hash: &[u8; 32],
//!     ) -> Result<(), ckb_transaction_cobuild::error::Error> {
//!         // Insert your authentication logic here
//!         Ok(())
//!     }
//! }
//! ```
//! - **`seal`**: Typically represents a signature.
//! - **`signing_message_hash`**: The hashed message that the owner signed.
//!   Together with the public key/pubkey hash, these components are verified
//!   using cryptographic algorithms.
//!
//! To support cobuild, proceed with calling `cobuild_entry`:
//! ```rust
//! let verifier = Verifier::new();
//! let cobuild_activated = cobuild_entry(&verifier)?;
//! ```
//! The boolean `cobuild_activated` denotes whether cobuild mode has been
//! enabled. If not, the script may default to executing its legacy code.
//!
//! ### For Type Script
//! To retrieve messages, use the `fetch_message` function. For comprehensive
//! details on utilizing messages and actions within the cobuild framework,
//! refer to the cobuild specification.
//!

#![no_std]
extern crate alloc;

pub mod blake2b;
pub mod error;
pub mod lazy_reader;
pub mod legacy;
pub mod log;
pub mod otx;
pub mod schemas;
pub mod schemas2;
pub mod sighashall;
pub mod utils;

use alloc::vec::Vec;
use ckb_std::{
    ckb_constants::Source,
    high_level::{load_cell_lock_hash, load_script_hash},
};
use error::Error;
use lazy_reader::new_transaction;
use otx::{fetch_otx_start, generate_otx_smh, OtxDynamicConfigs, OtxSigningRange};
use schemas2::{blockchain, top_level};
use sighashall::cobuild_normal_entry;
use utils::{cache_script_hashes, is_script_included, ScriptType};

///
/// This is the callback trait should be implemented in lock script by
/// developers.
///
/// - **`seal`**: Typically represents a signature.
/// - **`signing_message_hash`**: The hashed message that the owner signed.
pub trait Callback {
    fn invoke(&self, seal: &[u8], signing_message_hash: &[u8; 32]) -> Result<(), Error>;
}

#[derive(Debug)]
pub struct CobuildState {
    pub otx_start_index: usize,

    pub input_start: u32,
    pub input_end: u32,
    pub output_end: u32,
    pub cell_dep_end: u32,
    pub header_dep_end: u32,
}

/// Attempts to parse all witnesses into a `WitnessLayout` structure. Returns
/// `None` if parsing is not possible. For instance, parsing fails and returns
/// `None` if the structure is a `WitnessArgs`. The second return value
/// indicates whether the cobuild feature is activated (`true`) or not
/// (`false`).
fn parse_witness_layouts(
    tx: &blockchain::Transaction,
) -> Result<(Vec<Option<top_level::WitnessLayout>>, bool), Error> {
    let witness_layouts: Vec<Option<top_level::WitnessLayout>> = tx
        .witnesses()?
        .into_iter()
        .map(|w| top_level::WitnessLayout::try_from(w).ok())
        .collect();
    let mut activated = false;
    for w in witness_layouts.iter().flatten() {
        w.verify(false)?;
        activated = true;
    }
    Ok((witness_layouts, activated))
}

/// Serves as the primary entry point for a lock script supporting cobuild.
/// Operates in conjunction with the `Callback` trait. For integration
/// instructions into cobuild, refer to the crate documentation.
pub fn cobuild_entry<F: Callback>(verifier: F) -> Result<bool, Error> {
    let tx = new_transaction();
    let raw_tx = tx.raw()?;
    let (witness_layouts, cobuild_activated) = parse_witness_layouts(&tx)?;
    // Legacy Flow Handling
    if !cobuild_activated {
        return Ok(false);
    }

    let current_script_hash = load_script_hash()?;
    let script_hashes_cache = cache_script_hashes();
    // step 2
    // step 4
    let (otx_start, otx_start_index) = fetch_otx_start(&witness_layouts)?;
    if otx_start.is_none() {
        // step 3
        log!("No otx detected");
        cobuild_normal_entry(verifier, &script_hashes_cache)?;
        return Ok(true);
    }
    let otx_start = otx_start.unwrap();

    let start_input_cell: u32 = otx_start.start_input_cell()?;
    let start_output_cell: u32 = otx_start.start_output_cell()?;
    let start_cell_deps: u32 = otx_start.start_cell_deps()?;
    let start_header_deps: u32 = otx_start.start_header_deps()?;
    // step 5
    let mut state = CobuildState {
        otx_start_index,
        input_start: start_input_cell,
        input_end: start_input_cell,
        output_end: start_output_cell,
        cell_dep_end: start_cell_deps,
        header_dep_end: start_header_deps,
    };

    let mut execution_count: usize = 0;
    let mut otx_count = 0;
    log!("state: {:?}", state);
    log!("Otx starts at index {}(inclusive)", otx_start_index + 1);
    // this index is always pointing to the current processing OTX witness.
    let mut otx_witness_end_index = otx_start_index;
    for witness_index in otx_start_index + 1..witness_layouts.len() {
        otx_witness_end_index = witness_index;
        let witness = witness_layouts.get(witness_index).unwrap();
        if witness.is_none() {
            // step 6, not WitnessLayoutOtx
            break;
        }
        match witness {
            Some(top_level::WitnessLayout::Otx(ref otx)) => {
                otx_count += 1;

                let flag: u8 = otx.flag()?;
                let otx_configs: OtxDynamicConfigs = flag.try_into()?;

                let fixed_input_cells: u32 = otx.fixed_input_cells()?;
                let fixed_output_cells: u32 = otx.fixed_output_cells()?;
                let fixed_cell_deps: u32 = otx.fixed_cell_deps()?;
                let fixed_header_deps: u32 = otx.fixed_header_deps()?;

                if fixed_input_cells == 0
                    && fixed_output_cells == 0
                    && fixed_cell_deps == 0
                    && fixed_header_deps == 0
                {
                    return Err(Error::WrongCount);
                }

                let dynamic_input_cells: u32 = otx.dynamic_input_cells()?;
                let dynamic_output_cells: u32 = otx.dynamic_output_cells()?;
                let dynamic_cell_deps: u32 = otx.dynamic_cell_deps()?;
                let dynamic_header_deps: u32 = otx.dynamic_header_deps()?;

                if !otx_configs.dynamic_inputs && dynamic_input_cells != 0
                    || !otx_configs.dynamic_outputs && dynamic_output_cells != 0
                    || !otx_configs.dynamic_cell_deps && dynamic_cell_deps != 0
                    || !otx_configs.dynamic_header_deps && dynamic_header_deps != 0
                {
                    return Err(Error::WrongCount);
                }

                let lock_hash_existing_in_fixed = is_script_included(
                    &script_hashes_cache,
                    current_script_hash,
                    ScriptType::InputLock,
                    state.input_end as usize,
                    (state.input_end + fixed_input_cells) as usize,
                );

                let lock_hash_existing_in_dynamic = is_script_included(
                    &script_hashes_cache,
                    current_script_hash,
                    ScriptType::InputLock,
                    (state.input_end + fixed_input_cells) as usize,
                    (state.input_end + fixed_input_cells + dynamic_input_cells) as usize,
                );

                if !lock_hash_existing_in_fixed && !lock_hash_existing_in_dynamic {
                    state.input_end += fixed_input_cells + dynamic_input_cells;
                    state.output_end += fixed_output_cells + dynamic_output_cells;
                    state.cell_dep_end += fixed_cell_deps + dynamic_cell_deps;
                    state.header_dep_end += fixed_header_deps + dynamic_header_deps;
                    continue;
                }

                if lock_hash_existing_in_fixed {
                    // step 6.e
                    let fixed_smh = generate_otx_smh(
                        &raw_tx,
                        otx.message()?,
                        OtxSigningRange {
                            input_start: state.input_end,
                            inputs_count: fixed_input_cells,
                            output_start: state.output_end,
                            outputs_count: fixed_output_cells,
                            cell_dep_start: state.cell_dep_end,
                            cell_deps_count: fixed_cell_deps,
                            header_dep_start: state.header_dep_end,
                            header_deps_count: fixed_header_deps,
                        },
                    )?;
                    // step 6.f
                    let mut seal_found = false;
                    for index in 0..otx.seals()?.len()? {
                        let seal_pair = otx.seals()?.get(index)?;
                        if seal_pair.script_hash()? == current_script_hash.as_slice() {
                            let seal: Vec<u8> = seal_pair.seal()?.try_into()?;
                            log!("invoke OTX verifier");
                            verifier.invoke(&seal, &fixed_smh)?;
                            seal_found = true;
                            execution_count += 1;
                            break;
                            // duplicated seals are ignored
                        }
                    }

                    if !seal_found {
                        log!("seal can't be found");
                        return Err(Error::NoSealFound);
                    }
                }

                if lock_hash_existing_in_dynamic {
                    // step 6.e
                    let dynamic_smh = generate_otx_smh(
                        &raw_tx,
                        otx.message()?,
                        OtxSigningRange {
                            input_start: state.input_end,
                            inputs_count: fixed_input_cells + dynamic_input_cells,
                            output_start: state.output_end,
                            outputs_count: fixed_output_cells,
                            cell_dep_start: state.cell_dep_end,
                            cell_deps_count: fixed_cell_deps,
                            header_dep_start: state.header_dep_end,
                            header_deps_count: fixed_header_deps,
                        },
                    )?;
                    // step 6.f
                    let mut seal_found = false;
                    for index in (0..otx.seals()?.len()?).rev() {
                        let seal_pair = otx.seals()?.get(index)?;
                        if seal_pair.script_hash()? == current_script_hash.as_slice() {
                            let seal: Vec<u8> = seal_pair.seal()?.try_into()?;
                            log!("invoke OTX verifier");
                            verifier.invoke(&seal, &dynamic_smh)?;
                            seal_found = true;
                            execution_count += 1;
                            break;
                            // duplicated seals are ignored
                        }
                    }

                    if !seal_found {
                        log!("seal can't be found");
                        return Err(Error::NoSealFound);
                    }
                }

                // step 6.h
                state.input_end += fixed_input_cells + dynamic_input_cells;
                state.output_end += fixed_output_cells + dynamic_output_cells;
                state.cell_dep_end += fixed_cell_deps + dynamic_cell_deps;
                state.header_dep_end += fixed_header_deps + dynamic_header_deps;
            }
            _ => {
                break;
            }
        }
    } // end of step 6 loop

    // step 7
    // after the loop, the j points to the first non OTX witness or out of bounds
    let first_non_otx_witness_index = if otx_witness_end_index == (witness_layouts.len() - 1) {
        witness_layouts.len()
    } else {
        otx_witness_end_index
    };
    log!(
        "the first non OTX witness is at index {}",
        first_non_otx_witness_index
    );
    for loop_index in 0..witness_layouts.len() {
        // [0, i) [j, +infinity)
        if loop_index < otx_start_index || loop_index >= first_non_otx_witness_index {
            if let Some(Some(top_level::WitnessLayout::Otx(_))) = &witness_layouts.get(loop_index) {
                log!(
                    "WrongWitnessLayout at index = {} (i = {}, j = {}, otx_count = {})",
                    loop_index,
                    otx_start_index,
                    first_non_otx_witness_index,
                    otx_count
                );
                return Err(Error::WrongWitnessLayout);
            }
        }
    }
    // step 8
    let mut found = false;
    for index in 0..raw_tx.inputs()?.len()? {
        // scan all input cell in [0, is) and [ie, +infinity)
        // if is == ie, it is always true
        if index < state.input_start as usize || index >= state.input_end as usize {
            let hash = load_cell_lock_hash(index, Source::Input)?;
            if hash == current_script_hash {
                found = true;
                break;
            }
        }
    }
    if found {
        execution_count += 1;
        log!("extra callback is invoked");
        cobuild_normal_entry(verifier, &script_hashes_cache)?;
    }
    log!("execution_count = {}", execution_count);
    Ok(true)
}
