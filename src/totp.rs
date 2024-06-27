use crate::hash::HashFn;
use crate::hotp;
use crate::sha1::SHA1;

fn number_of_time_steps(t0: u64, current: u64, x: u64) -> u64 {
    (current - t0) / x
}

pub fn totp<const B: usize, const L: usize, H: HashFn<B, L>, F: Fn() -> H>(
    hash_new_fn: F,
    unix_time: u64,
    t0: u64,
    x: u64,
    digits: u32,
    key: &[u8],
) -> u32 {
    hotp::hotp(
        hash_new_fn,
        key,
        number_of_time_steps(t0, unix_time, x),
        digits,
    )
}

pub fn totp_default(unix_time: u64, key: &[u8]) -> u32 {
    totp(SHA1::new, unix_time, 0, 30, 6, key)
}

#[cfg(test)]
mod tests {
    use crate::{
        sha1::SHA1,
        totp::{number_of_time_steps, totp},
    };

    #[test]
    fn test_totp_rfc_vectors() {
        struct TestCase {
            time: u64,
            expected_t: u64,
            expected_totp_sha1: u32,
        }
        let test_cases = [
            TestCase {
                time: 59,
                expected_t: 0x0000000000000001,
                expected_totp_sha1: 94287082,
            },
            TestCase {
                time: 1111111109,
                expected_t: 0x00000000023523EC,
                expected_totp_sha1: 07081804,
            },
            TestCase {
                time: 1111111111,
                expected_t: 0x00000000023523ED,
                expected_totp_sha1: 14050471,
            },
            TestCase {
                time: 1234567890,
                expected_t: 0x000000000273EF07,
                expected_totp_sha1: 89005924,
            },
            TestCase {
                time: 2000000000,
                expected_t: 0x0000000003F940AA,
                expected_totp_sha1: 69279037,
            },
            TestCase {
                time: 20000000000,
                expected_t: 0x0000000027BC86AA,
                expected_totp_sha1: 65353130,
            },
        ];

        let secret = "12345678901234567890".as_bytes();

        for test_case in test_cases {
            assert!(number_of_time_steps(0, test_case.time, 30) == test_case.expected_t);
            assert!(
                totp(SHA1::new, test_case.time, 0, 30, 8, secret) == test_case.expected_totp_sha1
            )
        }
    }
}
