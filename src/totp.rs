use crate::hotp;

fn number_of_time_steps(t0: u64, current: u64, x: u64) -> u64 {
    (current - t0) / x
}

pub fn totp(unix_time: u64, t0: u64, x: u64, digits: u32, key: &[u8]) -> u32 {
    hotp::hotp(key, number_of_time_steps(t0, unix_time, x), digits)
}

pub fn totp_default(unix_time: u64, key: &[u8]) -> u32 {
    totp(unix_time, 0, 30, 6, key)
}