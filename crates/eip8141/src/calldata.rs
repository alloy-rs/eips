//! Calldata pricing helpers.

/// Returns the standard calldata token count of `data`.
///
/// This is EIP-8141's `tokens_in`: zero bytes count as one token and non-zero bytes as four. It
/// applies to every transaction field priced as calldata, not only frame data.
pub fn calldata_tokens(data: &[u8]) -> u64 {
    let zero_bytes = data.iter().filter(|byte| **byte == 0).count() as u64;
    zero_bytes + (data.len() as u64 - zero_bytes) * 4
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calldata_tokens_charge_zero_and_nonzero_bytes() {
        assert_eq!(calldata_tokens(&[]), 0);
        assert_eq!(calldata_tokens(&[0, 1, 0xff]), 9);
    }
}
