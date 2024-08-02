use ckb_gen_types::prelude::Unpack;
use ckb_std::{
    ckb_constants::Source,
    ckb_types::packed::Transaction,
    high_level::{self, load_cell, load_cell_data, load_cell_lock_hash, load_witness, QueryIter},
};
use core::convert::Into;
use molecule::prelude::{Entity, Reader};

use crate::{
    blake2b::new_otx_blake2b,
    error::Error,
    schemas::{
        basic::{OtxStart, SealPairVec},
        top_level::{WitnessLayoutReader, WitnessLayoutUnionReader},
    },
};

pub struct OtxDynamicConfigs {
    dynamic_inputs: bool,
    dynamic_outputs: bool,
    dynamic_cell_deps: bool,
    dynamic_header_deps: bool,
}

pub fn parse_otx_flag(flag: u8) -> Result<OtxDynamicConfigs, Error> {
    let dynamic_inputs = (flag & 0b00000001) != 0;
    let dynamic_outputs = (flag & 0b00000010) != 0;
    let dynamic_cell_deps = (flag & 0b00000100) != 0;
    let dynamic_header_deps = (flag & 0b00001000) != 0;

    if (flag & 0b11110000) != 0 {
        return Err(Error::InvalidOtxFlag);
    }

    Ok(OtxDynamicConfigs {
        dynamic_inputs,
        dynamic_outputs,
        dynamic_cell_deps,
        dynamic_header_deps,
    })
}

/// OtxMessageIter is an iterator over the otx message in current transaction
/// The item of this iterator is a tuple of signing_message_hash and SealPairVec
pub struct OtxMessageIter {
    tx: Transaction,
    current_script_hash: [u8; 32],
    witness_counter: usize,
    input_cell_counter: usize,
    output_cell_counter: usize,
    cell_deps_counter: usize,
    header_deps_counter: usize,
}

impl Iterator for OtxMessageIter {
    type Item = ([u8; 32], SealPairVec);

    fn next(&mut self) -> Option<Self::Item> {
        let witness_iter = self.tx.witnesses().into_iter().skip(self.witness_counter);
        let raw_tx = self.tx.raw();
        for witness in witness_iter {
            if let Ok(r) = WitnessLayoutReader::from_slice(&witness.raw_data()) {
                match r.to_enum() {
                    WitnessLayoutUnionReader::Otx(otx) => {
                        self.witness_counter += 1;
                        let flag: u8 = otx.flag().into();
                        let fixed_input_cells: u32 = otx.fixed_input_cells().unpack();
                        let fixed_output_cells: u32 = otx.fixed_output_cells().unpack();
                        let fixed_cell_deps: u32 = otx.fixed_cell_deps().unpack();
                        let fixed_header_deps: u32 = otx.fixed_header_deps().unpack();

                        let dynamic_input_cells: u32 = otx.fixed_input_cells().unpack();
                        let dynamic_output_cells: u32 = otx.fixed_output_cells().unpack();
                        let dynamic_cell_deps: u32 = otx.fixed_cell_deps().unpack();
                        let dynamic_header_deps: u32 = otx.fixed_header_deps().unpack();

                        let mut input_lock_hash_iter =
                            QueryIter::new(load_cell_lock_hash, Source::Input)
                                .skip(self.input_cell_counter)
                                .take(fixed_input_cells as usize);

                        if input_lock_hash_iter
                            .any(|lock_hash| lock_hash == self.current_script_hash)
                        {
                            let mut hasher = new_otx_blake2b();
                            // message
                            hasher.update(otx.message().as_slice());

                            // otx inputs
                            hasher.update(&fixed_input_cells.to_le_bytes());
                            let input_iter = raw_tx
                                .inputs()
                                .into_iter()
                                .skip(self.input_cell_counter)
                                .zip(
                                    QueryIter::new(load_cell, Source::Input)
                                        .skip(self.input_cell_counter),
                                )
                                .zip(
                                    QueryIter::new(load_cell_data, Source::Input)
                                        .skip(self.input_cell_counter),
                                );
                            for ((input, input_cell), input_cell_data) in
                                input_iter.take(fixed_input_cells as usize)
                            {
                                hasher.update(input.as_slice());
                                hasher.update(input_cell.as_slice());
                                hasher.update(&(input_cell_data.len() as u32).to_le_bytes());
                                hasher.update(&input_cell_data);
                            }
                            self.input_cell_counter += fixed_input_cells as usize;

                            // otx outputs
                            hasher.update(&fixed_output_cells.to_le_bytes());
                            let output_iter = raw_tx
                                .outputs()
                                .into_iter()
                                .skip(self.output_cell_counter)
                                .zip(
                                    raw_tx
                                        .outputs_data()
                                        .into_iter()
                                        .skip(self.output_cell_counter),
                                );
                            for (output_cell, output_cell_data) in
                                output_iter.take(fixed_output_cells as usize)
                            {
                                hasher.update(output_cell.as_slice());
                                // according to the spec, we need to hash the output data length first in little endian, then the data itself.
                                // we are using molecule serialized slice directly here, it's same as the spec.
                                hasher.update(output_cell_data.as_slice());
                            }
                            self.output_cell_counter += fixed_output_cells as usize;

                            // otx cell deps
                            hasher.update(&fixed_cell_deps.to_le_bytes());
                            let cell_dep_iter =
                                raw_tx.cell_deps().into_iter().skip(self.cell_deps_counter);
                            for cell_dep in cell_dep_iter.take(fixed_cell_deps as usize) {
                                hasher.update(cell_dep.as_slice());
                            }
                            self.cell_deps_counter += fixed_cell_deps as usize;

                            // otx header deps
                            hasher.update(&fixed_header_deps.to_le_bytes());
                            let header_dep_iter = raw_tx
                                .header_deps()
                                .into_iter()
                                .skip(self.header_deps_counter);
                            for header_dep in header_dep_iter.take(fixed_header_deps as usize) {
                                hasher.update(header_dep.as_slice());
                            }
                            self.header_deps_counter += fixed_header_deps as usize;

                            let mut result = [0u8; 32];
                            hasher.finalize(&mut result);
                            return Some((result, otx.seals().to_entity()));
                        } else {
                            self.input_cell_counter +=
                                fixed_input_cells as usize + dynamic_input_cells as usize;
                            self.output_cell_counter +=
                                fixed_output_cells as usize + dynamic_output_cells as usize;
                            self.cell_deps_counter +=
                                fixed_cell_deps as usize + dynamic_cell_deps as usize;
                            self.header_deps_counter +=
                                fixed_header_deps as usize + dynamic_header_deps as usize;
                        }
                    }
                    _ => return None,
                }
            } else {
                return None;
            }
        }

        None
    }
}

///
/// verify all otx messages with the given script hash and verify function
/// This function is mainly used by lock script
///
pub fn verify_otx_message<F: Fn(&[u8], &[u8; 32]) -> bool>(
    current_script_hash: [u8; 32],
    verify: F,
) -> Result<bool, Error> {
    let mut otx_message_iter = parse_otx_message(current_script_hash)?;
    let verified = otx_message_iter.all(|(message_digest, seals)| {
        seals
            .into_iter()
            .filter(|seal_pair| {
                seal_pair.script_hash().as_slice() == current_script_hash.as_slice()
            })
            .any(|seal_pair| verify(&seal_pair.seal().raw_data(), &message_digest))
    });
    Ok(verified)
}

///
/// parse transaction and return `OtxMessageIter`
/// This function is mainly used by lock script
///
pub fn parse_otx_message(current_script_hash: [u8; 32]) -> Result<OtxMessageIter, Error> {
    let (otx_start, start_index) = fetch_otx_start()?;
    let start_input_cell: u32 = otx_start.start_input_cell().unpack();
    let start_output_cell: u32 = otx_start.start_output_cell().unpack();
    let start_cell_deps: u32 = otx_start.start_cell_deps().unpack();
    let start_header_deps: u32 = otx_start.start_header_deps().unpack();

    let tx = high_level::load_transaction()?;

    Ok(OtxMessageIter {
        tx,
        current_script_hash,
        witness_counter: start_index + 1,
        input_cell_counter: start_input_cell as usize,
        output_cell_counter: start_output_cell as usize,
        cell_deps_counter: start_cell_deps as usize,
        header_deps_counter: start_header_deps as usize,
    })
}

fn fetch_otx_start() -> Result<(OtxStart, usize), Error> {
    let mut otx_start = None;
    let mut start_index = 0;
    let mut end_index = 0;

    for (i, witness) in QueryIter::new(load_witness, Source::Input).enumerate() {
        if let Ok(r) = WitnessLayoutReader::from_slice(&witness) {
            match r.to_enum() {
                WitnessLayoutUnionReader::OtxStart(o) => {
                    if otx_start.is_none() {
                        otx_start = Some(o.to_entity());
                        start_index = i;
                        end_index = i;
                    } else {
                        return Err(Error::WrongWitnessLayout);
                    }
                }
                WitnessLayoutUnionReader::Otx(_) => {
                    if otx_start.is_none() || end_index + 1 != i {
                        return Err(Error::WrongWitnessLayout);
                    } else {
                        end_index = i;
                    }
                }
                _ => {}
            }
        }
    }
    if let Some(otx_start) = otx_start {
        if end_index > 0 {
            return Ok((otx_start, start_index));
        }
    }
    Err(Error::WrongOtxStart)
}
