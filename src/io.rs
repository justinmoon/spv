use crate::error::Error;
use bitcoin::blockdata::{block::BlockHeader, constants::genesis_block};
use bitcoin::{FilterHash, Network};
use serde::{Deserialize, Serialize};
use serde_json;
use std::fs;
use std::fs::File;
use std::io::BufReader;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Db {
    pub headers: Vec<BlockHeader>,
    pub checkpoints: Vec<FilterHash>,
    pub filter_headers: Vec<FilterHash>,
    //#[serde(skip)]
    //pub filters: Vec<BlockFilter>,
}

impl Db {
    pub fn new() -> Self {
        // FIXME: don't assume mainnet
        let genesis_header = genesis_block(Network::Bitcoin).header;
        Self {
            headers: vec![genesis_header],
            checkpoints: vec![],
            filter_headers: vec![],
        }
    }

    pub fn read() -> Result<Self, Error> {
        if let Ok(file) = File::open("db.json") {
            let reader = BufReader::new(file);
            let db: Self = serde_json::from_reader(reader)?;
            return Ok(db);
        }
        Ok(Db::new())
    }

    pub fn save(&self) -> Result<(), Error> {
        let path = String::from("db.json");
        let serialized = serde_json::to_string(&self)?;
        fs::write(path, serialized)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::encode::deserialize;
    use hex::decode as hex_decode;

    #[test]
    fn simple_test() {
        let raw = hex_decode("010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914cd74d6e49ffff001d323b3a7b").unwrap();

        let header: BlockHeader =
            deserialize(&raw).expect("Can't deserialize correct block header");

        let headers = vec![header, header, header];
        let db = Db {
            headers,
            checkpoints: vec![],
            filter_headers: vec![],
        };
        db.save().unwrap();
        let from_disk = Db::read().unwrap();
        assert_eq!(db, from_disk);
    }
}
