use crate::error::Error;
use bitcoin::blockdata::block::BlockHeader;
use serde::{Deserialize, Serialize};
use serde_json;
use std::fs;
use std::fs::File;
use std::io::BufReader;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Db {
    pub headers: Vec<BlockHeader>,
}

impl Db {
    pub fn read() -> Result<Self, Error> {
        let file = File::open("db.json")?;
        let reader = BufReader::new(file);
        let db: Self = serde_json::from_reader(reader)?;
        Ok(db)
    }

    pub fn write(&self) -> Result<(), Error> {
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
        let db = Db { headers };
        db.write().unwrap();
        let from_disk = Db::read().unwrap();
        assert_eq!(db, from_disk);
    }
}
