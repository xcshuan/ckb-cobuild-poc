use alloc::{collections::btree_map::BTreeMap, vec::Vec};
use ckb_std::{
    ckb_constants::Source,
    high_level::{load_cell_lock_hash, load_cell_type_hash, QueryIter},
};

use crate::{error::Error, schemas2::basic::Message};

#[derive(Debug)]
pub enum ScriptType {
    InputLock,
    InputType,
    OutputType,
}

#[derive(Debug)]
pub struct ScriptLocation {
    pub input_lock: Vec<usize>,
    pub input_type: Vec<usize>,
    pub output_type: Vec<usize>,
}

pub fn cache_script_hashes() -> BTreeMap<[u8; 32], ScriptLocation> {
    let mut script_hashes_cache: BTreeMap<[u8; 32], ScriptLocation> = BTreeMap::new();

    QueryIter::new(load_cell_lock_hash, Source::Input)
        .enumerate()
        .for_each(|(index, lock_hash)| {
            script_hashes_cache
                .entry(lock_hash)
                .and_modify(|location| location.input_lock.push(index))
                .or_insert(ScriptLocation {
                    input_lock: [index].to_vec(),
                    input_type: Vec::new(),
                    output_type: Vec::new(),
                });
        });

    QueryIter::new(load_cell_type_hash, Source::Input)
        .enumerate()
        .for_each(|(index, input_type_hash)| {
            if let Some(input_type_hash) = input_type_hash {
                script_hashes_cache
                    .entry(input_type_hash)
                    .and_modify(|location| location.input_type.push(index))
                    .or_insert(ScriptLocation {
                        input_lock: Vec::new(),
                        input_type: [index].to_vec(),
                        output_type: Vec::new(),
                    });
            }
        });

    QueryIter::new(load_cell_type_hash, Source::Output)
        .enumerate()
        .for_each(|(index, output_type_hash)| {
            if let Some(output_type_hash) = output_type_hash {
                script_hashes_cache
                    .entry(output_type_hash)
                    .and_modify(|location| location.output_type.push(index))
                    .or_insert(ScriptLocation {
                        input_lock: Vec::new(),
                        input_type: Vec::new(),
                        output_type: [index].to_vec(),
                    });
            }
        });

    script_hashes_cache
}

pub fn is_script_exist(
    script_hashes_cache: &BTreeMap<[u8; 32], ScriptLocation>,
    script_hash: [u8; 32],
    script_type: ScriptType,
) -> bool {
    script_hashes_cache
        .get(&script_hash)
        .is_some_and(|location| match script_type {
            ScriptType::InputLock => !location.input_lock.is_empty(),
            ScriptType::InputType => !location.input_type.is_empty(),
            ScriptType::OutputType => !location.output_type.is_empty(),
        })
}

pub fn is_script_included(
    script_hashes_cache: &BTreeMap<[u8; 32], ScriptLocation>,
    script_hash: [u8; 32],
    script_type: ScriptType,
    start_index: usize,
    end_index: usize,
) -> bool {
    script_hashes_cache
        .get(&script_hash)
        .is_some_and(|location| match script_type {
            ScriptType::InputLock => !location
                .input_lock
                .iter()
                .any(|loc| *loc >= start_index && *loc < end_index),
            ScriptType::InputType => !location
                .input_type
                .iter()
                .any(|loc| *loc >= start_index && *loc < end_index),
            ScriptType::OutputType => !location
                .output_type
                .iter()
                .any(|loc| *loc >= start_index && *loc < end_index),
        })
}

pub fn check_message(
    script_hashes_cache: &BTreeMap<[u8; 32], ScriptLocation>,
    message: Message,
) -> Result<(), Error> {
    for action in message.actions()?.iter() {
        let script_type = match action.script_type()? {
            0 => ScriptType::InputLock,
            1 => ScriptType::InputType,
            2 => ScriptType::OutputType,
            _ => return Err(Error::WrongScriptType),
        };

        if !is_script_exist(script_hashes_cache, action.script_hash()?, script_type) {
            return Err(Error::ScriptHashAbsent);
        }
    }

    Ok(())
}
