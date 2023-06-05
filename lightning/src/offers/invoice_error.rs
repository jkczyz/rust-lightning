// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Data structures and encoding for `invoice_error` messages.

use core::convert::TryFrom;
use crate::io;
use crate::offers::parse::{ParseError, ParsedMessage, SemanticError};
use crate::util::ser::{HighZeroBytesDroppedBigSize, WithoutLength, Writeable, Writer};
use crate::util::string::UntrustedString;

use crate::prelude::*;

/// An error in response to an [`InvoiceRequest`] or an [`Invoice`].
///
/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
/// [`Invoice`]: crate::offers::invoice::Invoice
#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct InvoiceError {
	/// The field in the [`InvoiceRequest`] or the [`Invoice`] that contained an error.
	///
	/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
	/// [`Invoice`]: crate::offers::invoice::Invoice
	pub erroneous_field: Option<ErroneousField>,

	/// An explanation of the error.
	pub message: UntrustedString,
}

/// The field in the [`InvoiceRequest`] or the [`Invoice`] that contained an error.
///
/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
/// [`Invoice`]: crate::offers::invoice::Invoice
#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct ErroneousField {
	/// The type number of the TLV field containing the error.
	pub tlv_fieldnum: u64,

	/// A value to use for the TLV field to avoid the error.
	pub suggested_value: Option<Vec<u8>>,
}

impl InvoiceError {
	pub(super) fn as_tlv_stream(&self) -> InvoiceErrorTlvStreamRef {
		InvoiceErrorTlvStreamRef {
			erroneous_field: self.erroneous_field.as_ref().map(|f| f.tlv_fieldnum),
			suggested_value: self.erroneous_field.as_ref().and_then(|f| f.suggested_value.as_ref()),
			error: Some(&self.message),
		}
	}
}

impl core::fmt::Display for InvoiceError {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
		self.message.fmt(f)
	}
}

impl Writeable for InvoiceError {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		self.as_tlv_stream().write(writer)
	}
}

tlv_stream!(InvoiceErrorTlvStream, InvoiceErrorTlvStreamRef, 0..=u64::MAX, {
	(1, erroneous_field: (u64, HighZeroBytesDroppedBigSize)),
	(3, suggested_value: (Vec<u8>, WithoutLength)),
	(5, error: (UntrustedString, WithoutLength)),
});

impl TryFrom<Vec<u8>> for InvoiceError {
	type Error = ParseError;

	fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
		let invoice_error = ParsedMessage::<InvoiceErrorTlvStream>::try_from(bytes)?;
		let ParsedMessage { tlv_stream, .. } = invoice_error;
		let InvoiceErrorTlvStream { erroneous_field, suggested_value, error } = tlv_stream;

		let erroneous_field = match (erroneous_field, suggested_value) {
			(None, None) => None,
			(None, Some(_)) => {
				return Err(ParseError::InvalidSemantics(SemanticError::MissingErroneousField));
			},
			(Some(tlv_fieldnum), suggested_value) => {
				Some(ErroneousField { tlv_fieldnum, suggested_value })
			},
		};

		let message = match error {
			None => return Err(ParseError::InvalidSemantics(SemanticError::MissingErrorMessage)),
			Some(error) => error,
		};

		Ok(InvoiceError { erroneous_field, message })
	}
}

impl From<SemanticError> for InvoiceError {
	fn from(error: SemanticError) -> Self {
		InvoiceError {
			erroneous_field: None,
			message: UntrustedString(format!("{:?}", error)),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::{ErroneousField, InvoiceError, InvoiceErrorTlvStreamRef};

	use core::convert::TryFrom;
	use crate::offers::parse::{ParseError, SemanticError};
	use crate::util::ser::Writeable;
	use crate::util::string::UntrustedString;

	#[test]
	fn parses_invoice_error_without_erroneous_field() {
		let message = UntrustedString("Invalid value".to_string());
		let tlv_stream = InvoiceErrorTlvStreamRef {
			erroneous_field: None,
			suggested_value: None,
			error: Some(&message),
		};

		let mut buffer = Vec::new();
		tlv_stream.write(&mut buffer).unwrap();

		match InvoiceError::try_from(buffer) {
			Ok(invoice_error) => {
				assert_eq!(invoice_error.message, UntrustedString("Invalid value".to_string()));
				assert_eq!(invoice_error.erroneous_field, None);
				assert_eq!(invoice_error.as_tlv_stream(), tlv_stream);
			}
			Err(e) => panic!("Unexpected error: {:?}", e),
		}
	}

	#[test]
	fn parses_invoice_error_with_erroneous_field() {
		let suggested_value = vec![42; 32];
		let message = UntrustedString("Invalid value".to_string());
		let tlv_stream = InvoiceErrorTlvStreamRef {
			erroneous_field: Some(42),
			suggested_value: Some(&suggested_value),
			error: Some(&message),
		};

		let mut buffer = Vec::new();
		tlv_stream.write(&mut buffer).unwrap();

		match InvoiceError::try_from(buffer) {
			Ok(invoice_error) => {
				assert_eq!(invoice_error.message, UntrustedString("Invalid value".to_string()));
				assert_eq!(
					invoice_error.erroneous_field,
					Some(ErroneousField {
						tlv_fieldnum: 42,
						suggested_value: Some(vec![42; 32])
					}),
				);
				assert_eq!(invoice_error.as_tlv_stream(), tlv_stream);
			}
			Err(e) => panic!("Unexpected error: {:?}", e),
		}
	}

	#[test]
	fn parses_invoice_error_without_suggested_value() {
		let message = UntrustedString("Invalid value".to_string());
		let tlv_stream = InvoiceErrorTlvStreamRef {
			erroneous_field: Some(42),
			suggested_value: None,
			error: Some(&message),
		};

		let mut buffer = Vec::new();
		tlv_stream.write(&mut buffer).unwrap();

		match InvoiceError::try_from(buffer) {
			Ok(invoice_error) => {
				assert_eq!(invoice_error.message, UntrustedString("Invalid value".to_string()));
				assert_eq!(
					invoice_error.erroneous_field,
					Some(ErroneousField { tlv_fieldnum: 42, suggested_value: None }),
				);
				assert_eq!(invoice_error.as_tlv_stream(), tlv_stream);
			}
			Err(e) => panic!("Unexpected error: {:?}", e),
		}
	}

	#[test]
	fn fails_parsing_invoice_error_without_message() {
		let tlv_stream = InvoiceErrorTlvStreamRef {
			erroneous_field: None,
			suggested_value: None,
			error: None,
		};

		let mut buffer = Vec::new();
		tlv_stream.write(&mut buffer).unwrap();

		match InvoiceError::try_from(buffer) {
			Ok(_) => panic!("Expected error"),
			Err(e) => {
				assert_eq!(e, ParseError::InvalidSemantics(SemanticError::MissingErrorMessage));
			},
		}
	}

	#[test]
	fn fails_parsing_invoice_error_without_field() {
		let suggested_value = vec![42; 32];
		let tlv_stream = InvoiceErrorTlvStreamRef {
			erroneous_field: None,
			suggested_value: Some(&suggested_value),
			error: None,
		};

		let mut buffer = Vec::new();
		tlv_stream.write(&mut buffer).unwrap();

		match InvoiceError::try_from(buffer) {
			Ok(_) => panic!("Expected error"),
			Err(e) => {
				assert_eq!(e, ParseError::InvalidSemantics(SemanticError::MissingErroneousField));
			},
		}
	}
}
