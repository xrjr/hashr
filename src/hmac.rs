use std::io::{Read, Error};

use crate::sha1;

pub fn hmac_sha1<R>(r: R, key: &[u8]) -> Result<[u8; sha1::OUTPUT_BYTE_LENGTH], Error> where R: Read {
    let mut final_key = [0u8; sha1::BLOCK_BYTE_LENGTH];
    final_key[..key.len()].copy_from_slice(key);

    let ipad = [0x36u8; sha1::BLOCK_BYTE_LENGTH];
    let opad = [0x5cu8; sha1::BLOCK_BYTE_LENGTH];

    let mut key_ipad = [0u8; 64];

    for (i, (&x1, &x2)) in final_key.iter().zip(ipad.iter()).enumerate() {
        key_ipad[i] = x1 ^ x2;
    }

    let mut appended_stream = key_ipad.as_slice().chain(r);

    let first_hash = sha1::digest_from_reader(&mut appended_stream)?;

    let mut key_opad = [0u8; 64];

    for (i, (&x1, &x2)) in final_key.iter().zip(opad.iter()).enumerate() {
        key_opad[i] = x1 ^ x2;
    }

    let mut second_appended_stream = key_opad.as_slice().chain(first_hash.as_slice());

    sha1::digest_from_reader(&mut second_appended_stream)
}