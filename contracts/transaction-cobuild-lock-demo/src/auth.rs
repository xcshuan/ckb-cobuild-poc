use ckb_hash::blake2b_256;
use secp256k1::{
    ecdsa::{RecoverableSignature, RecoveryId},
    Message, Secp256k1,
};

use crate::error::Error;

pub fn ckb_auth(
    pubkey_hash: [u8; 20],
    signature: &[u8],
    message_digest: &[u8; 32],
) -> Result<(), Error> {
    if signature.len() != 65 {
        return Err(Error::Encoding);
    }
    let signature = if let Ok(recid) = RecoveryId::from_i32(signature[64] as i32) {
        match RecoverableSignature::from_compact(&signature[0..64], recid) {
            Ok(recoverable_signature) => recoverable_signature,
            Err(_) => return Err(Error::Encoding),
        }
    } else {
        return Err(Error::Encoding);
    };

    let secp = Secp256k1::new();
    let public_key = match secp.recover_ecdsa(&Message::from_digest(*message_digest), &signature) {
        Ok(public_key) => public_key,
        Err(_) => return Err(Error::AuthFailed),
    };

    let recovered_pk_hash = blake2b_256(public_key.serialize().as_slice())[0..20].to_vec();
    if pubkey_hash != recovered_pk_hash.as_slice() {
        return Err(Error::AuthFailed);
    }

    Ok(())
}
