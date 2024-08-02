use ckb_std::{
    ckb_types::{bytes::Bytes, prelude::*},
    high_level::{load_script, load_script_hash},
};
use ckb_transaction_cobuild::otx::verify_otx_message;
use core::result::Result;

use crate::{auth::ckb_auth, error::Error};

pub fn main() -> Result<(), Error> {
    let mut pubkey_hash = [0u8; 20];
    let script = load_script()?;
    let args: Bytes = script.args().unpack();
    let current_script_hash = load_script_hash()?;
    pubkey_hash.copy_from_slice(&args[0..20]);

    let verify = |seal: &[u8], message_digest: &[u8; 32]| {
        let auth_result = ckb_auth(pubkey_hash, seal, message_digest);
        auth_result.is_ok()
    };
    let verify_pass = verify_otx_message(current_script_hash, verify)?;
    if verify_pass {
        Ok(())
    } else {
        Err(Error::AuthFailed)
    }
}
