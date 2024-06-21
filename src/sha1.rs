const BLOCK_SIZE: usize = 64; // 512 bits = 64 Bytes
const TRAILING_MESSAGE_LENGTH_SIZE: usize = 8; // u64 = 8 bytes
const ONE_PADDED_BYTE_SIZE: usize = 1;
use std::io::{Error, Read};

fn k(t: usize) -> u32 {
    if t < 20 {
        0x5A827999
    } else if t < 40 {
        0x6ED9EBA1
    } else if t < 60 {
        0x8F1BBCDC
    } else {
        0xCA62C1D6
    }
}

fn s(n: usize, x: u32) -> u32 {
    (x << n) | (x >> (32 - n))
}

fn f(t: usize, b: u32, c: u32, d: u32) -> u32 {
    if t < 20 {
        (b & c) | ((!b) & d)
    } else if t < 40 {
        b ^ c ^ d
    } else if t < 60 {
        (b & c) | (b & d) | (c & d)
    } else {
        b ^ c ^ d
    }
}

fn compute_block(h: &mut [u32; 5], block: &[u8; BLOCK_SIZE]) {
    let mut w = [0u32; 80];
    for (i, w_i) in w.iter_mut().enumerate().take(16) {
        let mut buf: [u8; 4] = [0u8; 4];
        buf.copy_from_slice(&block[i * 4..i * 4 + 4]);
        *w_i = u32::from_be_bytes(buf);
    }

    for t in 16..80 {
        w[t] = s(1, w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16])
    }

    let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);

    for (t, _) in w.iter().enumerate() {
        let temp: u32 = s(5, a)
            .wrapping_add(f(t, b, c, d))
            .wrapping_add(e)
            .wrapping_add(w[t])
            .wrapping_add(k(t));

        e = d;
        d = c;
        c = s(30, b);
        b = a;
        a = temp;
    }

    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
}

fn compute_with_padding(h: &mut [u32; 5], buf: &[u8; BLOCK_SIZE], total_size: usize) {
    let n_zeroes = number_of_zero_bytes(total_size);
    let last_index = total_size % BLOCK_SIZE;

    let mut vbuf = [0u8; 2 * BLOCK_SIZE];
    vbuf[0..last_index].copy_from_slice(&buf[0..last_index]);

    vbuf[last_index] = 0b10000000;

    let zeroes_start_index = last_index+1;
    let zeroes_end_index = zeroes_start_index + n_zeroes;
    vbuf[zeroes_start_index..zeroes_end_index].fill(0b00000000);

    let total_size_bytes: [u8; TRAILING_MESSAGE_LENGTH_SIZE] = (total_size * 8).to_be_bytes();

    vbuf[zeroes_end_index..zeroes_end_index+TRAILING_MESSAGE_LENGTH_SIZE].copy_from_slice(&total_size_bytes);

    compute_block(h, &vbuf[..BLOCK_SIZE].try_into().unwrap());

    if last_index > BLOCK_SIZE - ONE_PADDED_BYTE_SIZE - TRAILING_MESSAGE_LENGTH_SIZE {
        compute_block(h, &vbuf[BLOCK_SIZE..].try_into().unwrap());
    }
}

fn default_h() -> [u32; 5] {
    [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
}

pub fn digest_from_reader<R>(r: &mut R) -> Result<[u8; 20], Error>
where
    R: Read,
{
    let mut total_size = 0;
    let mut h  = default_h();

    let mut buf = [0u8; BLOCK_SIZE];
    let mut last_byte_index_in_buffer = 0;

    loop {
        let n = r.read(&mut buf[last_byte_index_in_buffer..BLOCK_SIZE])?;

        if n == 0 {
            // EOF
            break;
        }

        last_byte_index_in_buffer += n;
        if last_byte_index_in_buffer == BLOCK_SIZE {
            //block is complete
            last_byte_index_in_buffer = 0;
            compute_block(&mut h, &buf)
        }

        total_size += n;
    }

    compute_with_padding(&mut h, &buf, total_size);

    let mut res = [0u8; 20];

    res[0..4].copy_from_slice(&h[0].to_be_bytes());
    res[4..8].copy_from_slice(&h[1].to_be_bytes());
    res[8..12].copy_from_slice(&h[2].to_be_bytes());
    res[12..16].copy_from_slice(&h[3].to_be_bytes());
    res[16..20].copy_from_slice(&h[4].to_be_bytes());

    Ok(res)
}

fn number_of_zero_bytes(message_length: usize) -> usize {
    (BLOCK_SIZE - ((message_length + ONE_PADDED_BYTE_SIZE + TRAILING_MESSAGE_LENGTH_SIZE) % BLOCK_SIZE)) % BLOCK_SIZE
}

#[cfg(test)]
mod tests {
    use std::{io::Cursor, time};

    use crate::{hex::{self, decode_hex, encode_hex}, sha1};
    use super::digest_from_reader;


    fn read_lines<P>(filename: P) -> std::io::Result<std::io::Lines<std::io::BufReader<std::fs::File>>> where P: AsRef<std::path::Path> {
        use std::io::BufRead;
        let file = std::fs::File::open(filename)?;
        Ok(std::io::BufReader::new(file).lines())
    }

    #[test]
    fn test_sha1reader_dgst_zero_size() {
        let a: Vec<u8> = Vec::new();
        assert!(encode_hex(&digest_from_reader(&mut Cursor::new(a)).unwrap()).eq_ignore_ascii_case("da39a3ee5e6b4b0d3255bfef95601890afd80709"))
    }

    #[test]
    fn test_sha1reader_dgst_from_file() {
        let start = time::Instant::now();
        if let Ok(lines) = read_lines("./sha1.generated-testcases") {
            for line in lines.flatten() {
                let test_case: Vec<&str> = line.split(' ').collect();
                let input = decode_hex(*test_case.get(0).unwrap()).unwrap();
                let mut input = input.as_slice();
                let output = decode_hex(test_case.get(1).unwrap()).unwrap();
                let output = output.as_slice();

                let dgst = sha1::digest_from_reader(&mut input).unwrap();

                assert!(output.eq(&dgst));
            }
        }
        let elapsed = start.elapsed();
        println!("reader {}", elapsed.as_millis());
    }
}