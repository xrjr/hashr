// const BLOCK_LENGTH: usize = 64; // 512 bits = 64 Bytes

pub struct SHA1 {
    message: Vec<u8>
}

impl SHA1 {
    pub fn new(message: &[u8]) -> Self {
        Self{
            message: Vec::from(message)
        }
    }

    pub fn add_padding(&mut self) {
        let initial_length: u64 = self.message.len() as u64;
        let n_zeroes = (56u64.wrapping_sub(initial_length).wrapping_sub(1)) % 64;
        self.message.push(0b10000000);
        
        for _ in 0..n_zeroes {
            self.message.push(0b00000000);
        }

        for b in (initial_length * 8).to_be_bytes() {
            self.message.push(b);
        }
    }

    pub fn display_hex(&self) {
        println!("{:02X?}", self.message.as_slice());
    }

    fn f(t: usize, b: u32, c: u32, d: u32) -> u32 {
        if t < 20 {
            (b & c) | ((!b) & d)
        } else if t < 40 {
            b ^ c ^ d
        } else if t < 60  {
            (b & c) | (b & d) | (c & d)
        } else {
            b ^ c ^ d
        }
    }

    fn k(t: usize) -> u32 {
        if t < 20 {
            0x5A827999
        } else if t < 40 {
            0x6ED9EBA1
        } else if t < 60  {
            0x8F1BBCDC
        } else {
            0xCA62C1D6
        }
    }

    fn s(n: usize, x: u32) -> u32 {
        (x<<n) | (x>>(32-n))
    }

    pub fn digest(self) -> [u8; 20] {
        let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
        for block_number in 0..self.message.len()/64 {

            let mut w = [0u32; 80];
            for (i, w_i) in w.iter_mut().enumerate().take(16) {
                let mut buf: [u8; 4] = [0u8; 4];
                buf.copy_from_slice(&self.message[block_number * 64 + i * 4..block_number * 64 + i * 4 + 4]);
                *w_i = u32::from_be_bytes(buf);
            }

            for t in 16..80 {
                w[t] = Self::s(1, w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16])
            }

            let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);

            for (t, _) in w.iter().enumerate() {
                let temp: u32 = Self::s(5, a).wrapping_add(Self::f(t,b,c,d)).wrapping_add(e).wrapping_add(w[t]).wrapping_add(Self::k(t));

                e = d;
                d = c;
                c = Self::s(30, b);
                b = a;
                a = temp;
            }

            h[0] = h[0].wrapping_add(a);
            h[1] = h[1].wrapping_add(b);
            h[2] = h[2].wrapping_add(c);
            h[3] = h[3].wrapping_add(d);
            h[4] = h[4].wrapping_add(e);
        }

        let mut res = [0u8; 20];

        res[0..4].copy_from_slice(&h[0].to_be_bytes());
        res[4..8].copy_from_slice(&h[1].to_be_bytes());
        res[8..12].copy_from_slice(&h[2].to_be_bytes());
        res[12..16].copy_from_slice(&h[3].to_be_bytes());
        res[16..20].copy_from_slice(&h[4].to_be_bytes());

        res
    }
}

#[cfg(test)]
mod tests {
    use super::SHA1;
    use crate::hex::{decode_hex, encode_hex};


    fn read_lines<P>(filename: P) -> std::io::Result<std::io::Lines<std::io::BufReader<std::fs::File>>> where P: AsRef<std::path::Path> {
        use std::io::BufRead;
        let file = std::fs::File::open(filename)?;
        Ok(std::io::BufReader::new(file).lines())
    }

    #[test]
    fn test_sha1_dgst_zero_size() {
        let mut sha1 = SHA1::new(&[]);
        sha1.add_padding();
        assert!(encode_hex(&sha1.digest()).eq_ignore_ascii_case("da39a3ee5e6b4b0d3255bfef95601890afd80709"))
    }

    #[test]
    fn test_sha1_dgst_from_file() {
        if let Ok(lines) = read_lines("./sha1.generated-testcases") {
            for line in lines.flatten() {
                let test_case: Vec<&str> = line.split(' ').collect();
                let input = decode_hex(*test_case.get(0).unwrap()).unwrap();
                let input = input.as_slice();
                let output = decode_hex(test_case.get(1).unwrap()).unwrap();
                let output = output.as_slice();

                let mut sha1 = SHA1::new(input);
                sha1.add_padding();
                let dgst = sha1.digest();

                assert!(output.eq(&dgst));
            }
        }
    }
}