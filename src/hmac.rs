use std::io::{Error, Read};

use crate::{hash::HashFn, sha1::{self, SHA1}};

pub struct HMAC<const B: usize, const L: usize, H: HashFn<B, L>> {
    key_opad: [u8; sha1::BLOCK_BYTE_LENGTH],
    sha1state: H,
}

type HMACSHA1 = HMAC<64, 20, sha1::SHA1>;

impl<const B: usize, const L: usize, H: HashFn<B, L>> HMAC<B, L, H> {
    pub fn new(key: &[u8]) -> Self {
        let mut final_key = [0u8; sha1::BLOCK_BYTE_LENGTH];
        if key.len() > sha1::BLOCK_BYTE_LENGTH {
            final_key[..sha1::OUTPUT_BYTE_LENGTH].copy_from_slice(&sha1::digest_from_bytes(key));
        } else {
            final_key[..key.len()].copy_from_slice(key);
        }

        let mut key_ipad = [0x36; sha1::BLOCK_BYTE_LENGTH];
        let mut key_opad = [0x5c; sha1::BLOCK_BYTE_LENGTH];
        for i in 0..sha1::BLOCK_BYTE_LENGTH {
            key_ipad[i] ^= final_key[i];
            key_opad[i] ^= final_key[i];
        }

        let mut sha1state = H::new();
        sha1state.update(key_ipad.as_slice());
        Self {
            sha1state,
            key_opad,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.sha1state.update(data);
    }

    pub fn finalize(&mut self) -> [u8; L] {
        let first_hash = self.sha1state.finalize();
        let mut second_sha1_state = H::new();
        second_sha1_state.update(&self.key_opad);
        second_sha1_state.update(&first_hash);
        second_sha1_state.finalize()
    }
}

pub fn sha1_digest_from_bytes(data: &[u8], key: &[u8]) -> [u8; sha1::OUTPUT_BYTE_LENGTH] {
    let mut hmac_sha1_state = HMACSHA1::new(key);
    hmac_sha1_state.update(data);
    hmac_sha1_state.finalize()
}

pub fn sha1_digest_from_reader<R>(
    mut r: R,
    key: &[u8],
) -> Result<[u8; sha1::OUTPUT_BYTE_LENGTH], Error>
where
    R: Read,
{
    let mut hmac_sha1_state = HMACSHA1::new(key);
    let mut buf = [0u8; 512];

    loop {
        let n = r.read(&mut buf)?;

        if n == 0 {
            break;
        }

        hmac_sha1_state.update(&buf[..n]);
    }

    Ok(hmac_sha1_state.finalize())
}

#[cfg(test)]
mod tests {
    use crate::hex;

    use super::sha1_digest_from_bytes;

    #[test]
    fn test_hmac_sha1_rfc_test_vectors() {
        struct TestCase {
            key: Vec<u8>,
            data: Vec<u8>,
            expected_digest: Vec<u8>,
        }
        let tests_cases: Vec<TestCase> = vec![
            TestCase {
                key: hex::decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap(),
                data: Vec::from("Hi There"),
                expected_digest: hex::decode_hex("b617318655057264e28bc0b6fb378c8ef146be00")
                    .unwrap(),
            },
            TestCase {
                key: Vec::from("Jefe"),
                data: Vec::from("what do ya want for nothing?"),
                expected_digest: hex::decode_hex("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79")
                    .unwrap(),
            },
            TestCase {
                key: hex::decode_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
                data: Vec::from([0xdd; 50]),
                expected_digest: hex::decode_hex("125d7342b9ac11cd91a39af48aa17b4f63f175d3")
                    .unwrap(),
            },
            TestCase {
                key: hex::decode_hex("0102030405060708090a0b0c0d0e0f10111213141516171819").unwrap(),
                data: Vec::from([0xcd; 50]),
                expected_digest: hex::decode_hex("4c9007f4026250c6bc8414f9bf50c86c2d7235da")
                    .unwrap(),
            },
            TestCase {
                key: hex::decode_hex("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c").unwrap(),
                data: Vec::from("Test With Truncation"),
                expected_digest: hex::decode_hex("4c1a03424b55e07fe7f27be1d58bb9324a9a5a04")
                    .unwrap(),
            },
            TestCase {
                key: Vec::from([0xaa; 80]),
                data: Vec::from("Test Using Larger Than Block-Size Key - Hash Key First"),
                expected_digest: hex::decode_hex("aa4ae5e15272d00e95705637ce8a3b55ed402112")
                    .unwrap(),
            },
            TestCase {
                key: Vec::from([0xaa; 80]),
                data: Vec::from(
                    "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data",
                ),
                expected_digest: hex::decode_hex("e8e99d0f45237d786d6bbaa7965c7808bbff1a91")
                    .unwrap(),
            },
        ];

        for test_case in tests_cases {
            let digest = sha1_digest_from_bytes(test_case.data.as_slice(), &test_case.key);
            assert!(digest.eq(test_case.expected_digest.as_slice()))
        }
    }
}
