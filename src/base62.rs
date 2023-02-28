use anyhow;
pub const ALPHABET: &[u8] = r"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".as_bytes();

/// This specialised base62 encoder converts exactly 32 bytes to exactly 43 characters.
/// This is a very efficient encoding chunk size, as log2(62)*43 == 256.03 bits.
pub fn encode(input: &[u8; 32]) -> String
{
    let mut output = [0u8; 43];
    let mut index = 0;
    for &val in input {
        let mut carry = val as usize;
        for byte in &mut output[..index] {
            carry += (*byte as usize) << 8;
            *byte = (carry % 62) as u8;
            carry /= 62;
        }
        while carry > 0 {
            if index == output.len() {
                panic!("buffer too small");
            }
            output[index] = (carry % 62) as u8;
            index += 1;
            carry /= 62;
        }
    }

    for _ in input.into_iter().take_while(|v| **v == 0) {
        if index == output.len() {
            panic!("buffer too small");
        }
        output[index] = 0;
        index += 1;
    }

    for val in &mut output {
        *val = ALPHABET[*val as usize];
    }

    output.reverse();
    String::from_utf8(output.to_vec()).expect("ALPHABET contained non-ASCII values")
}

/// This specialised base62 decoder converts exactly 43 characters to exactly 32 bytes.
/// This is a very efficient encoding chunk size, as log2(62)*43 == 256.03 bits.
pub fn decode(base62: &str) -> anyhow::Result<[u8; 32]> {
    let mut index = 0;
    let input = base62.as_bytes();
    let mut output = [0u8; 32];

    for (i, c) in input.iter().enumerate() {
        if *c > 127 {
            return Err(anyhow::anyhow!("non-ascii character, index: {i}"));
        }

        if i == 43 {
            break // Ignore any characters after the first 43.
        }

        let mut val = match ALPHABET.iter().position(|&x| x == *c) { // FIXME: too slow
            Some(val) => val,
            None => {
                let character = *c as char;
                return Err(anyhow::anyhow!("invalid character: '{character}' at index: {i}"));
            }
        };

        for byte in &mut output[..index] {
            val += (*byte as usize) * 62;
            *byte = (val & 0xFF) as u8;
            val >>= 8;
        }

        while val > 0 {
            let byte = output.get_mut(index).ok_or(anyhow::anyhow!("buffer too small"))?;
            *byte = (val & 0xFF) as u8;
            index += 1;
            val >>= 8
        }
    }

    output.reverse();
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode() {
        assert_eq!(encode(&[0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0]),
            "0000000000000000000000000000000000000000000");
        assert_eq!(encode(&[0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,1]),
            "0000000000000000000000000000000000000000001");
        assert_eq!(encode(&[0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,61]),
            "000000000000000000000000000000000000000000z");
        assert_eq!(encode(&[0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,62]),
            "0000000000000000000000000000000000000000010");
        assert_eq!(encode(&[0xFF; 32]),
            "yhjskwdA6OZ1AL1YmHWZWm8LLG7HjnuCA2j5rOw8Xp1");
    }

    #[test]
    fn test_decode() {
        assert_eq!(decode("0000000000000000000000000000000000000000000").unwrap(),
            [0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0]);
        assert_eq!(decode("0000000000000000000000000000000000000000001").unwrap(),
            [0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,1]);
        assert_eq!(decode("000000000000000000000000000000000000000000z").unwrap(),
            [0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,61]);
        assert_eq!(decode("0000000000000000000000000000000000000000010").unwrap(),
            [0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,62]);
        assert_eq!(decode("yhjskwdA6OZ1AL1YmHWZWm8LLG7HjnuCA2j5rOw8Xp1").unwrap(),
            [0xFF; 32]);
        // TODO: test short strings, long strings and invalid characters
    }
}