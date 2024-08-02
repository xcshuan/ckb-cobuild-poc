use alloc::vec::Vec;
use ckb_std::{
    ckb_constants::Source,
    ckb_types::packed::CellInput,
    error::SysError,
    high_level::{load_cell, load_cell_data, load_tx_hash, load_witness, QueryIter},
    syscalls::load_transaction,
};
use core::convert::Into;
use molecule::{
    prelude::{Entity, Reader},
    NUMBER_SIZE,
};

use crate::{
    blake2b::{new_sighash_all_blake2b, new_sighash_all_only_blake2b},
    error::Error,
    schemas::{
        basic::Message,
        top_level::{WitnessLayoutReader, WitnessLayoutUnionReader},
    },
};

///
/// fetch the seal field of SighashAll or SighashAllOnly in current script group
///
fn fetch_seal() -> Result<Vec<u8>, Error> {
    match load_witness(0, Source::GroupInput) {
        Ok(witness) => {
            if let Ok(r) = WitnessLayoutReader::from_slice(&witness) {
                match r.to_enum() {
                    WitnessLayoutUnionReader::SighashAll(s) => Ok(s.seal().raw_data().to_vec()),
                    WitnessLayoutUnionReader::SighashAllOnly(s) => Ok(s.seal().raw_data().to_vec()),
                    _ => Err(Error::MoleculeEncoding),
                }
            } else {
                Err(Error::MoleculeEncoding)
            }
        }
        Err(e) => Err(e.into()),
    }
}

///
/// fetch the message field of SighashAll
/// returns None if there is no SighashAll witness
/// returns Error::WrongWitnessLayout if there are more than one SighashAll witness
pub fn fetch_message() -> Result<Option<Message>, Error> {
    let mut iter = QueryIter::new(load_witness, Source::Input).filter_map(|witness| {
        WitnessLayoutReader::from_slice(&witness)
            .ok()
            .and_then(|r| match r.to_enum() {
                WitnessLayoutUnionReader::SighashAll(s) => Some(s.message().to_entity()),
                _ => None,
            })
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
    if QueryIter::new(load_witness, Source::GroupInput)
        .skip(1)
        .all(|witness| witness.is_empty())
    {
        Ok(())
    } else {
        Err(Error::WrongWitnessLayout)
    }
}

fn generate_signing_message_hash(message: &Option<Message>) -> Result<[u8; 32], Error> {
    // message
    let mut hasher = match message {
        Some(m) => {
            let mut hasher = new_sighash_all_blake2b();
            hasher.update(m.as_slice());
            hasher
        }
        None => new_sighash_all_only_blake2b(),
    };
    // tx hash
    hasher.update(&load_tx_hash()?);
    // inputs cell and data
    let inputs_len = calculate_inputs_len()?;
    for i in 0..inputs_len {
        let input_cell = load_cell(i, Source::Input)?;
        hasher.update(input_cell.as_slice());
        // TODO cell data may be too large, use high_level::load_data fn to load and hash it in chunks
        let input_cell_data = load_cell_data(i, Source::Input)?;
        hasher.update(&(input_cell_data.len() as u32).to_le_bytes());
        hasher.update(&input_cell_data);
    }
    // extra witnesses
    for witness in QueryIter::new(load_witness, Source::Input).skip(inputs_len) {
        hasher.update(&(witness.len() as u32).to_le_bytes());
        hasher.update(&witness);
    }

    let mut result = [0u8; 32];
    hasher.finalize(&mut result);
    Ok(result)
}

///
/// the molecule data structure of transaction is:
/// full-size|raw-offset|witnesses-offset|raw-full-size|version-offset|cell_deps-offset|header_deps-offset|inputs-offset|outputs-offset|...
/// full-size and offset are 4 bytes, so we can read the inputs-offset and outputs-offset at [28, 36),
/// then we can get the length of inputs by calculating the difference between inputs-offset and outputs-offset
///
fn calculate_inputs_len() -> Result<usize, SysError> {
    let mut offsets = [0u8; 8];
    match load_transaction(&mut offsets, 28) {
        // this syscall will always return SysError::LengthNotEnough since we only load 8 bytes, let's ignore it
        Err(SysError::LengthNotEnough(_)) => {}
        Err(SysError::Unknown(e)) => return Err(SysError::Unknown(e)),
        _ => unreachable!(),
    }
    let inputs_offset = u32::from_le_bytes(offsets[0..4].try_into().unwrap());
    let outputs_offset = u32::from_le_bytes(offsets[4..8].try_into().unwrap());
    Ok((outputs_offset as usize - inputs_offset as usize - NUMBER_SIZE) / CellInput::TOTAL_SIZE)
}

///
/// parse transaction with message and return 2 values:
/// 1. signing_message_hash, 32 bytes message for signature verification
/// 2. seal, seal field in SighashAll or SighashAllOnly. Normally as signature.
///    This function is mainly used by lock script
///
pub fn parse_message() -> Result<([u8; 32], Vec<u8>), Error> {
    check_others_in_group()?;
    let message = fetch_message()?;
    let signing_message_hash = generate_signing_message_hash(&message)?;
    let seal = fetch_seal()?;
    Ok((signing_message_hash, seal))
}
