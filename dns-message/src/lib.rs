mod builder;
mod error;
mod header;
mod message;
mod parser;
mod question;
mod resource_record;

use error::MessageError;
use tracing::instrument;

pub use builder::{MessageBuilder, QuestionBuilder, ResourceRecordBuilder};
pub use header::{Header, OpCode, RCode};
pub use message::Message;
pub use question::{Class, Question, Type};
pub use resource_record::{RData, ResourceRecord};

type Result<T> = std::result::Result<T, MessageError>;

#[instrument(skip(buf))]
pub(crate) fn encode_str(s: &str, buf: &mut Vec<u8>) -> Result<usize> {
    let mut byte_count = 0;
    let name_parts = s.split(".");
    for name in name_parts {
        if name.len() > 63 {
            return Err(MessageError::NameLengthExceeded(
                name.len(),
                name.to_string(),
            ));
        }
        let len = name.len() as u8;
        buf.push(len);
        byte_count += 1;
        for b in name.bytes() {
            buf.push(b);
            byte_count += 1;
        }
    }
    buf.push(0);
    byte_count += 1;
    Ok(byte_count)
}

#[cfg(test)]
mod test {
    use std::sync::Once;

    static INIT: Once = Once::new();

    pub fn setup() {
        INIT.call_once(|| {
            tracing_subscriber::fmt::init();
        });
    }
}
