use ckb_std::{
    ckb_types::{bytes::Bytes, prelude::*},
    debug,
    high_level::load_script,
};
use ckb_transaction_cobuild::parse_message;
use core::result::Result;

use crate::{auth::ckb_auth, error::Error};

pub fn main() -> Result<(), Error> {
    if let Ok((message_digest, seal)) = parse_message() {
        let mut pubkey_hash = [0u8; 20];
        let script = load_script()?;
        let args: Bytes = script.args().unpack();
        pubkey_hash.copy_from_slice(&args[0..20]);

        ckb_auth(pubkey_hash, &seal, &message_digest)?;

        Ok(())
    } else {
        // In this routine, it indicates that the WitnessLayout is not being
        // used. It is possible that the traditional WitnessArgs is being used.
        // The previous code can be copied and pasted here.
        Ok(())
    }
}
