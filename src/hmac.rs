use std::io::{Error, Read};

use crate::{hash::HashFn, sha1::SHA1};

pub struct HMAC<const B: usize, const L: usize, H: HashFn<B, L>, F: Fn() -> H> {
    key_opad: [u8; B],
    hash_state: H,
    hash_new_fn: F,
}

impl<const B: usize, const L: usize, H: HashFn<B, L>, F: Fn() -> H> HMAC<B, L, H, F> {
    pub fn new(hash_new_fn: F, key: &[u8]) -> Self {
        let mut final_key = [0u8; B];
        if key.len() > B {
            let mut key_hasher = hash_new_fn();
            key_hasher.update(key);
            final_key[..L].copy_from_slice(&key_hasher.finalize());
        } else {
            final_key[..key.len()].copy_from_slice(key);
        }

        let mut key_ipad = [0x36; B];
        let mut key_opad = [0x5c; B];
        for i in 0..B {
            key_ipad[i] ^= final_key[i];
            key_opad[i] ^= final_key[i];
        }

        let mut sha1state = hash_new_fn();
        sha1state.update(key_ipad.as_slice());
        Self {
            hash_state: sha1state,
            key_opad,
            hash_new_fn,
        }
    }
}

impl<const B: usize, const L: usize, H: HashFn<B, L>, F: Fn() -> H> HashFn<B, L>
    for HMAC<B, L, H, F>
{
    fn update(&mut self, data: &[u8]) {
        self.hash_state.update(data);
    }

    fn finalize(&mut self) -> [u8; L] {
        let first_hash = self.hash_state.finalize();
        let f = &self.hash_new_fn;
        let mut second_sha1_state = f();
        second_sha1_state.update(&self.key_opad);
        second_sha1_state.update(&first_hash);
        second_sha1_state.finalize()
    }
}

pub fn sha1_digest_from_bytes(data: &[u8], key: &[u8]) -> [u8; SHA1::OUTPUT_SIZE] {
    let mut hmac_sha1_state = HMAC::new(SHA1::new, key);
    hmac_sha1_state.update(data);
    hmac_sha1_state.finalize()
}

pub fn sha1_digest_from_reader<R>(mut r: R, key: &[u8]) -> Result<[u8; SHA1::OUTPUT_SIZE], Error>
where
    R: Read,
{
    let mut hmac_sha1_state = HMAC::new(SHA1::new, key);
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
