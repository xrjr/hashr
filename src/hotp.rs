use crate::{hmac::hmac_sha1, sha1};

pub fn hotp(key: &[u8], counter: u64, digits: u32) -> u32 {
    let hs = hmac_sha1(counter.to_be_bytes().as_slice(), key)
        .expect("should remove this by not necessiting a reader");
    let snum = dt(&hs);
    snum % 10u32.pow(digits)
}

// dynamic truncation of sha1 digest
fn dt(hs: &[u8; sha1::OUTPUT_BYTE_LENGTH]) -> u32 {
    let offset = (hs[19] & 0xf) as usize;
    ((hs[offset] & 0x7f) as u32) << 24
        | ((hs[offset + 1] & 0xff) as u32) << 16
        | ((hs[offset + 2] & 0xff) as u32) << 8
        | ((hs[offset + 3] & 0xff) as u32)
}

#[cfg(test)]
mod tests {
    use super::{dt, hotp};
    use crate::{hex, hmac};

    #[test]
    fn test_hotp_hmac_sha1_rfc() {
        let secret = hex::decode_hex("3132333435363738393031323334353637383930").unwrap();
        let expected: [&'static str; 10] = [
            "cc93cf18508d94934c64b65d8ba7667fb7cde4b0",
            "75a48a19d4cbe100644e8ac1397eea747a2d33ab",
            "0bacb7fa082fef30782211938bc1c5e70416ff44",
            "66c28227d03a2d5529262ff016a1e6ef76557ece",
            "a904c900a64b35909874b33e61c5938a8e15ed1c",
            "a37e783d7b7233c083d4f62926c7a25f238d0316",
            "bc9cd28561042c83f219324d3c607256c03272ae",
            "a4fb960c0bc06e1eabb804e5b397cdc4b45596fa",
            "1b3c89f65e6c9e883012052823443f048b4332db",
            "1637409809a679dc698207310c8c7fc07290d9e5",
        ];

        for i in 0..expected.len() {
            let hs = hmac::hmac_sha1(i.to_be_bytes().as_slice(), secret.as_slice()).unwrap();
            let expected = hex::decode_hex(expected[i]).unwrap();
            let expected = expected.as_slice();
            assert!(hs.eq(expected));
        }
    }

    #[test]
    fn test_hotp_dt_rfc() {
        let secret = hex::decode_hex("3132333435363738393031323334353637383930").unwrap();
        let expected: [u32; 10] = [
            1284755224, 1094287082, 137359152, 1726969429, 1640338314, 868254676, 1918287922,
            82162583, 673399871, 645520489,
        ];

        for i in 0..expected.len() {
            let hs = hmac::hmac_sha1(i.to_be_bytes().as_slice(), secret.as_slice()).unwrap();
            assert!(dt(&hs) == expected[i]);
        }
    }

    #[test]
    fn test_hotp_hotp_rfc() {
        let secret = hex::decode_hex("3132333435363738393031323334353637383930").unwrap();
        let expected: [u32; 10] = [
            755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489,
        ];

        for i in 0..expected.len() {
            assert!(hotp(secret.as_slice(), i as u64, 6) == expected[i])
        }
    }
}
