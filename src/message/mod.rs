mod error;
mod message;
mod parser;

use parser::Name;
use tracing::{error, instrument};

pub use message::{Flags, Header, Message, Question, ResourceRecord};

#[instrument]
fn flatten_to_string(names: &Vec<Name>) -> String {
    let mut name = String::new();
    for n in names.iter() {
        match n {
            Name::Name(part) => {
                name.push_str(part);
                name.push('.');
            }
            Name::ResolvedPtr(names) => {
                let s = flatten_to_string(names);
                name.push_str(&s);
            }
            Name::Pointer(_i) => {
                // TODO - Fix this so that we resolve all pointers.
                // This however should not happen now that we recursively resolve the names.
                error!("WARNING - FOUND UNRESOLVED POINTER....SKIPPING");
            }
        }
    }
    // Remove the trailing '.'
    if name.chars().last() == Some('.') {
        name.pop();
    }
    name
}
