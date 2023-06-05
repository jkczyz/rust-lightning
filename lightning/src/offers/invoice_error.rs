// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Data structures and encoding for `invoice_error` messages.

use crate::io;
use crate::ln::msgs::DecodeError;
use crate::offers::parse::SemanticError;
use crate::util::ser::{HighZeroBytesDroppedBigSize, Readable, WithoutLength, Writeable, Writer};
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

impl core::fmt::Display for InvoiceError {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
		self.message.fmt(f)
	}
}

impl Writeable for InvoiceError {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		write_tlv_fields!(writer, {
			(1, self.erroneous_field.tlv_fieldnum, (option, encoding: (u64, HighZeroBytesDroppedBigSize))),
			(3, self.erroneous_field.suggested_value, (option, encoding: (Vec<u8>, WithoutLength))),
			(5, WithoutLength(self.message), required),
		});
	}
}

impl Readable for InvoiceError {
	fn read<R: io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let mut erroneous_field = None;
		let mut suggested_value = None;
		let mut error = None;
		read_tlv_fields!(reader, {
			(1, erroneous_field, (option, encoding: (u64, HighZeroBytesDroppedBigSize))),
			(3, suggested_value, (option, encoding: (Vec<u8>, WithoutLength))),
			(5, error, (option, encoding: (UntrustedString, WithoutLength))),
		});

		let erroneous_field = match (erroneous_field, suggested_value) {
			(None, None) => None,
			(None, Some(_)) => return Err(DecodeError::InvalidValue),
			(Some(tlv_fieldnum), suggested_value) => {
				Some(ErroneousField { tlv_fieldnum, suggested_value })
			},
		};

		let message = match error {
			None => return Err(DecodeError::InvalidValue),
			Some(message) => message,
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
