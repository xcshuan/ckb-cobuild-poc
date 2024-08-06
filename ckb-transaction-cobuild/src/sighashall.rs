use alloc::{collections::btree_map::BTreeMap, vec::Vec};
use ckb_std::{ckb_constants::Source, error::SysError, high_level::load_tx_hash, syscalls};
use molecule::lazy_reader::Cursor;

use crate::{
    blake2b::{new_sighash_all_blake2b, new_sighash_all_only_blake2b},
    error::Error,
    lazy_reader::{self, new_input_cell_data, new_transaction, new_witness},
    log, parse_witness_layouts,
    schemas2::{basic, top_level},
    utils::{is_script_exist, ScriptLocation},
    Callback, ScriptType,
};

///
/// fetch the seal field of SighashAll or SighashAllOnly in current script group
///
fn fetch_seal() -> Result<Vec<u8>, Error> {
    let witness = new_witness(0, Source::GroupInput)?;
    let witness = top_level::WitnessLayout::try_from(witness)?;
    match witness {
        top_level::WitnessLayout::SighashAll(s) => {
            let seal: Vec<u8> = s.seal()?.try_into()?;
            Ok(seal)
        }
        top_level::WitnessLayout::SighashAllOnly(s) => {
            let seal: Vec<u8> = s.seal()?.try_into()?;
            Ok(seal)
        }
        _ => Err(Error::MoleculeEncoding),
    }
}

/// Retrieves the `message` field from a `SighashAll` witness.
/// - Returns `None` if a `SighashAll` witness is not present.
/// - Returns `Error::WrongWitnessLayout` if multiple `SighashAll` witnesses are
///   found. This function is intended for use within type scripts and lock
///   scripts.
pub fn fetch_message() -> Result<Option<basic::Message>, Error> {
    let tx = new_transaction();
    let (witness_layouts, _) = parse_witness_layouts(&tx)?;

    let mut iter = witness_layouts.iter().filter_map(|witness| match witness {
        Some(top_level::WitnessLayout::SighashAll(m)) => Some(m.message().unwrap().clone()),
        _ => None,
    });

    match (iter.next(), iter.next()) {
        (Some(message), None) => Ok(Some(message)),
        (None, None) => Ok(None),
        _ => Err(Error::WrongWitnessLayout),
    }
}

///
/// for lock script with message, the other witness in script group except
/// first one should be empty
///
fn check_others_in_group() -> Result<(), Error> {
    let mut index = 1;
    let mut buf = [0u8; 4];
    loop {
        let r = syscalls::load_witness(&mut buf, 0, index, Source::GroupInput);
        match r {
            Ok(actual_length) => {
                if actual_length > 0 {
                    return Err(Error::WrongWitnessLayout);
                }
            }
            Err(SysError::LengthNotEnough(_)) => return Err(Error::WrongWitnessLayout),
            _ => break,
        }
        index += 1;
    }
    Ok(())
}

///
/// Generate signing message hash for SighashAll or SighashAllOnly.
///
fn generate_signing_message_hash(message: &Option<basic::Message>) -> Result<[u8; 32], Error> {
    let tx = new_transaction();

    // message
    let mut hasher = match message {
        Some(m) => {
            let mut hasher = new_sighash_all_blake2b();
            hasher.update_cursor(m.cursor.clone());
            hasher
        }
        None => new_sighash_all_only_blake2b(),
    };
    // tx hash
    hasher.update(&load_tx_hash()?);
    // inputs cell and data
    let inputs = tx.raw()?.inputs()?;
    let inputs_len = inputs.len()?;
    for i in 0..inputs_len {
        let reader = lazy_reader::InputCellReader::try_new(i, Source::Input)?;
        let cursor: Cursor = reader.into();
        hasher.update_cursor(cursor);

        let cursor = new_input_cell_data(i, Source::Input)?;
        hasher.update(&(cursor.size as u32).to_le_bytes());
        hasher.update_cursor(cursor);
    }
    // extra witnesses
    for witness in tx.witnesses()?.iter().skip(inputs_len) {
        hasher.update(&(witness.size as u32).to_le_bytes());
        hasher.update_cursor(witness);
    }
    let mut result = [0u8; 32];
    let count = hasher.count();
    hasher.finalize(&mut result);
    log!(
        "generate_signing_message_hash totally hashed {} bytes, hash = {:?}",
        count,
        result
    );
    Ok(result)
}

pub fn cobuild_normal_entry<F: Callback>(
    verifier: F,
    script_hashes_cache: &BTreeMap<[u8; 32], ScriptLocation>,
) -> Result<(), Error> {
    check_others_in_group()?;
    let message = fetch_message()?;
    let signing_message_hash = generate_signing_message_hash(&message)?;
    let seal = fetch_seal()?;
    verifier.invoke(&seal, &signing_message_hash)?;

    if let Some(message) = message {
        for action in message.actions()?.iter() {
            let script_type = match action.script_type()? {
                0 => ScriptType::InputLock,
                1 => ScriptType::InputType,
                2 => ScriptType::OutputType,
                _ => return Err(Error::WrongSighashAll),
            };

            if !is_script_exist(script_hashes_cache, action.script_hash()?, script_type) {
                return Err(Error::ScriptHashAbsent);
            }
        }
    }

    Ok(())
}
