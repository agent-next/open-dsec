//! Minimal standard base64 (file bodies travel inside JSON frames).

const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

pub fn decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let mut buf = 0u32;
    let mut bits = 0;
    for ch in s.bytes().filter(|b| *b != b'=') {
        let v = T.iter().position(|&t| t == ch)? as u32;
        buf = buf << 6 | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_rfc4648_vectors() {
        for (p, e) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encode(p.as_bytes()), e);
            assert_eq!(decode(e).unwrap(), p.as_bytes());
        }
    }

    #[test]
    fn roundtrips_all_byte_values_and_rejects_garbage() {
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(decode(&encode(&all)).unwrap(), all);
        assert!(decode("a$b").is_none());
    }
}
