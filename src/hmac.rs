use std::io::{Error, Read};

use crate::sha1;

pub fn hmac_sha1<R>(r: R, key: &[u8]) -> Result<[u8; sha1::OUTPUT_BYTE_LENGTH], Error> where R: Read {
    let mut final_key = [0u8; sha1::BLOCK_BYTE_LENGTH];
    if key.len() > sha1::BLOCK_BYTE_LENGTH {
        final_key[..sha1::OUTPUT_BYTE_LENGTH].copy_from_slice(&sha1::digest_from_reader(&mut &key[..])?);
    } else {
        final_key[..key.len()].copy_from_slice(key);
    }

    let mut key_ipad = [0x36; sha1::BLOCK_BYTE_LENGTH];
    let mut key_opad = [0x5c; sha1::BLOCK_BYTE_LENGTH];
    for i in 0..sha1::BLOCK_BYTE_LENGTH {
        key_ipad[i] ^= final_key[i];
        key_opad[i] ^= final_key[i];
    }

    let mut appended_stream = key_ipad.as_slice().chain(r);
    let first_hash = sha1::digest_from_reader(&mut appended_stream)?;
    let mut second_appended_stream = key_opad.as_slice().chain(first_hash.as_slice());

    sha1::digest_from_reader(&mut second_appended_stream)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use crate::hex;

    use super::hmac_sha1;

    #[test]
    fn test_hmac_sha1_rfc_test_vectors() {
        struct TestCase {
            key: Vec<u8>,
            data: Vec<u8>,
            expected_digest: Vec<u8>
        }
        let tests_cases: Vec<TestCase> = vec![
            TestCase{
                key: hex::decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap(),
                data: Vec::from("Hi There"),
                expected_digest: hex::decode_hex("b617318655057264e28bc0b6fb378c8ef146be00").unwrap()
            },
            TestCase{
                key: Vec::from("Jefe"),
                data: Vec::from("what do ya want for nothing?"),
                expected_digest: hex::decode_hex("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79").unwrap()
            },
            TestCase{
                key: hex::decode_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
                data: Vec::from([0xdd; 50]),
                expected_digest: hex::decode_hex("125d7342b9ac11cd91a39af48aa17b4f63f175d3").unwrap()
            },
            TestCase{
                key: hex::decode_hex("0102030405060708090a0b0c0d0e0f10111213141516171819").unwrap(),
                data: Vec::from([0xcd; 50]),
                expected_digest: hex::decode_hex("4c9007f4026250c6bc8414f9bf50c86c2d7235da").unwrap()
            },
            TestCase{
                key: hex::decode_hex("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c").unwrap(),
                data: Vec::from("Test With Truncation"),
                expected_digest: hex::decode_hex("4c1a03424b55e07fe7f27be1d58bb9324a9a5a04").unwrap()
            },
            TestCase{
                key: Vec::from([0xaa; 80]),
                data: Vec::from("Test Using Larger Than Block-Size Key - Hash Key First"),
                expected_digest: hex::decode_hex("aa4ae5e15272d00e95705637ce8a3b55ed402112").unwrap()
            },
            TestCase{
                key: Vec::from([0xaa; 80]),
                data: Vec::from("Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"),
                expected_digest: hex::decode_hex("e8e99d0f45237d786d6bbaa7965c7808bbff1a91").unwrap()
            }
        ];


        for test_case in tests_cases {
            let digest = hmac_sha1(Cursor::new(test_case.data), &test_case.key).unwrap();
            assert!(digest.eq(test_case.expected_digest.as_slice()))
        }
    }
}