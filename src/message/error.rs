use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum MessageError {
    ParsingError(String),
    EncodingError(Box<dyn Error + Send + Sync>),
    CircularReference(String),
    ReservedOpCode,
    NameLengthExceeded(usize, String),
}

impl Error for MessageError {}

impl fmt::Display for MessageError {
    fn fmt(&self, f: &mut fmt::Formatter) -> std::result::Result<(), fmt::Error> {
        write!(f, "InvalidMessageError: {}", self)?;
        Ok(())
    }
}

impl<E: std::fmt::Debug> From<nom::Err<E>> for MessageError {
    fn from(error: nom::Err<E>) -> Self {
        MessageError::ParsingError(format!("Parsing error: {}", error))
    }
}

impl From<std::str::Utf8Error> for MessageError {
    fn from(error: std::str::Utf8Error) -> Self {
        MessageError::EncodingError(Box::new(error))
    }
}

impl From<std::string::FromUtf8Error> for MessageError {
    fn from(error: std::string::FromUtf8Error) -> Self {
        MessageError::EncodingError(Box::new(error))
    }
}
