use crate::hotp;
use crate::hash::HashFn;
use crate::sha1::SHA1;

fn number_of_time_steps(t0: u64, current: u64, x: u64) -> u64 {
    (current - t0) / x
}

pub fn totp<const B: usize, const L: usize, H: HashFn<B, L>, F: Fn() -> H>(hash_new_fn: F, unix_time: u64, t0: u64, x: u64, digits: u32, key: &[u8]) -> u32 {
    hotp::hotp(hash_new_fn, key, number_of_time_steps(t0, unix_time, x), digits)
}

pub fn totp_default(unix_time: u64, key: &[u8]) -> u32 {
    totp(SHA1::new, unix_time, 0, 30, 6, key)
}