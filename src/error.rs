use bitcoin;
use serde_json;
use std::{error, fmt, io};

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Bitcoin(bitcoin::Error),
    Serialize(bitcoin::consensus::encode::Error),
    Json(serde_json::Error),
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::Io(e)
    }
}

impl From<bitcoin::Error> for Error {
    fn from(e: bitcoin::Error) -> Error {
        Error::Bitcoin(e)
    }
}

impl From<bitcoin::consensus::encode::Error> for Error {
    fn from(e: bitcoin::consensus::encode::Error) -> Error {
        Error::Serialize(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Error {
        Error::Json(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Io(ref e) => write!(f, "I/O error: {}", e),
            Error::Bitcoin(ref e) => write!(f, "rust-bitcoin error: {:?}", e),
            Error::Serialize(ref e) => write!(f, "rust-bitcoin serialization error: {:?}", e),
            Error::Json(ref e) => write!(f, "Json error: {:?}", e),
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        "junction error"
    }

    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            Error::Io(ref e) => Some(e),
            _ => None,
        }
    }
}

