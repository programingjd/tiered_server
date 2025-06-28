pub(crate) fn hex_to_bytes(hex: &[u8], mut out: Vec<u8>) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    for it in hex.chunks(2) {
        let mut b = 0_u8;
        let first = it[0].to_ascii_lowercase();
        if first.is_ascii_digit() {
            b += 0x10 * (first - b'0');
        } else if (b'a'..=b'f').contains(&first) {
            b += 0x10 * (first - b'a' + 10);
        } else {
            return None;
        }
        let second = it[1].to_ascii_lowercase();
        if second.is_ascii_digit() {
            b += second - b'0';
        } else if (b'a'..=b'f').contains(&second) {
            b += second - b'a' + 10;
        } else {
            return None;
        }
        out.push(b);
    }
    Some(out)
}

pub(crate) fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
