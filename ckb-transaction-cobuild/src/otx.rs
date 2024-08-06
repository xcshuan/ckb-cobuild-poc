use ckb_std::ckb_constants::Source;
use molecule::lazy_reader::Cursor;

use crate::{
    blake2b::new_otx_blake2b,
    error::Error,
    lazy_reader::{self, new_input_cell_data},
    log,
    schemas2::{
        basic::{self, Message},
        blockchain, top_level,
    },
};

pub struct OtxDynamicConfigs {
    pub dynamic_inputs: bool,
    pub dynamic_outputs: bool,
    pub dynamic_cell_deps: bool,
    pub dynamic_header_deps: bool,
}

impl TryFrom<u8> for OtxDynamicConfigs {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let dynamic_inputs = (value & 0b00000001) != 0;
        let dynamic_outputs = (value & 0b00000010) != 0;
        let dynamic_cell_deps = (value & 0b00000100) != 0;
        let dynamic_header_deps = (value & 0b00001000) != 0;

        if (value & 0b11110000) != 0 {
            return Err(Error::InvalidOtxFlag);
        }

        Ok(OtxDynamicConfigs {
            dynamic_inputs,
            dynamic_outputs,
            dynamic_cell_deps,
            dynamic_header_deps,
        })
    }
}

pub struct OtxSigningRange {
    pub input_start: u32,
    pub inputs_count: u32,
    pub output_start: u32,
    pub outputs_count: u32,
    pub cell_dep_start: u32,
    pub cell_deps_count: u32,
    pub header_dep_start: u32,
    pub header_deps_count: u32,
}

/// generate OTX signing message hash
pub fn generate_otx_smh(
    raw_tx: &blockchain::RawTransaction,
    message: Message,
    signing_range: OtxSigningRange,
) -> Result<[u8; 32], Error> {
    let mut hasher = new_otx_blake2b();
    hasher.update_cursor(message.cursor.clone());
    hasher.update(&signing_range.inputs_count.to_le_bytes());

    let inputs = raw_tx.inputs()?;
    for index in signing_range.input_start as usize
        ..(signing_range.input_start + signing_range.inputs_count) as usize
    {
        // input
        hasher.update_cursor(inputs.get(index)?.cursor);

        let reader = lazy_reader::InputCellReader::try_new(index, Source::Input)?;
        let cursor: Cursor = reader.into();
        let data_cursor = new_input_cell_data(index, Source::Input)?;
        // input cell
        hasher.update_cursor(cursor);
        // input cell data size
        hasher.update(&(data_cursor.size as u32).to_le_bytes());
        // input cell data
        hasher.update_cursor(data_cursor);
    }

    hasher.update(&signing_range.outputs_count.to_le_bytes());

    for index in signing_range.output_start as usize
        ..(signing_range.output_start + signing_range.outputs_count) as usize
    {
        let outputs = raw_tx.outputs()?;
        let outputs_data = raw_tx.outputs_data()?;
        // output cell
        hasher.update_cursor(outputs.get(index)?.cursor);
        let data = outputs_data.get(index)?;
        // output cell data size
        hasher.update(&(data.size as u32).to_le_bytes());
        // output cell data
        hasher.update_cursor(data);
    }

    hasher.update(&signing_range.cell_deps_count.to_le_bytes());

    for index in signing_range.cell_dep_start as usize
        ..(signing_range.cell_dep_start + signing_range.cell_deps_count) as usize
    {
        let cell_deps = raw_tx.cell_deps()?;
        hasher.update_cursor(cell_deps.get(index)?.cursor)
    }

    hasher.update(&signing_range.header_deps_count.to_le_bytes());

    for index in signing_range.header_dep_start as usize
        ..(signing_range.header_dep_start + signing_range.header_deps_count) as usize
    {
        let header_deps = raw_tx.header_deps()?;
        hasher.update(&header_deps.get(index)?);
    }

    let mut result = [0u8; 32];
    let count = hasher.count();
    hasher.finalize(&mut result);
    log!(
        "generate_otx_smh totally hashed {} bytes and hash is {:?}",
        count,
        result
    );
    Ok(result)
}

///
/// parse all witnesses and find out the `OtxStart`
///
pub fn fetch_otx_start(
    witnesses: &[Option<top_level::WitnessLayout>],
) -> Result<(Option<basic::OtxStart>, usize), Error> {
    let mut otx_start = None;
    let mut start_index = 0;
    let mut end_index = 0;

    for (i, witness) in witnesses.iter().enumerate() {
        if let Some(witness_layout) = witness {
            match witness_layout {
                top_level::WitnessLayout::OtxStart(start) => {
                    if otx_start.is_none() {
                        otx_start = Some(start.clone());
                        start_index = i;
                        end_index = i;
                    } else {
                        log!("Duplicated OtxStart found");
                        return Err(Error::WrongWitnessLayout);
                    }
                }
                top_level::WitnessLayout::Otx(_) => {
                    if otx_start.is_none() {
                        log!("A Otx without OtxStart found");
                        return Err(Error::WrongWitnessLayout);
                    } else if end_index + 1 != i {
                        log!("Otx are not continuous");
                        return Err(Error::WrongWitnessLayout);
                    } else {
                        end_index = i;
                    }
                }
                _ => {}
            }
        }
    }

    if otx_start.is_some() {
        if end_index > 0 {
            Ok((otx_start, start_index))
        } else {
            log!("end_index == 0, there is no OTX");
            Err(Error::WrongOtxStart)
        }
    } else {
        Ok((None, 0))
    }
}
