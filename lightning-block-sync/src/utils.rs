use bitcoin::hashes::hex::{FromHex, HexToArrayError};
use bitcoin::pow::Work;

pub fn hex_to_work(hex: &str) -> Result<Work, HexToArrayError> {
	let bytes = <[u8; 32]>::from_hex(hex)?;
	Ok(Work::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests {
	use super::*;
	use bitcoin::hashes::hex::HexToBytesError;
	use bitcoin::pow::Work;

	#[test]
	fn hex_to_work_empty_str() {
		assert!(hex_to_work("").is_err());
	}

	#[test]
	fn hex_to_work_too_short_str() {
		let hex = String::from_utf8(vec![b'0'; 32]).unwrap();
		assert_eq!(hex_to_work(&hex), Err(HexToArrayError::InvalidLength(32, 64)));
	}

	#[test]
	fn hex_to_work_too_long_str() {
		let hex = String::from_utf8(vec![b'0'; 128]).unwrap();
		assert_eq!(hex_to_work(&hex), Err(HexToArrayError::InvalidLength(128, 64)));
	}

	#[test]
	fn hex_to_work_odd_length_str() {
		let hex = String::from_utf8(vec![b'0'; 65]).unwrap();
		assert_eq!(
			hex_to_work(&hex),
			Err(HexToArrayError::Conversion(HexToBytesError::OddLengthString(65)))
		);
	}

	#[test]
	fn hex_to_work_invalid_char() {
		let hex = String::from_utf8(vec![b'G'; 64]).unwrap();
		assert_eq!(
			hex_to_work(&hex),
			Err(HexToArrayError::Conversion(HexToBytesError::InvalidChar(b'G')))
		);
	}

	#[test]
	fn hex_to_work_lowercase_str() {
		let hex: String = std::iter::repeat("1a").take(32).collect();
		assert_eq!(hex_to_work(&hex).unwrap(), Work::from_be_bytes([0x1a; 32]));
	}

	#[test]
	fn hex_to_work_uppercase_str() {
		let hex: String = std::iter::repeat("1A").take(32).collect();
		assert_eq!(hex_to_work(&hex).unwrap(), Work::from_be_bytes([0x1A; 32]));
	}
}
