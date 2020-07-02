use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, process};

use crate::error::Error;
use bitcoin::blockdata::{
    block::{Block, BlockHeader},
    constants::genesis_block,
    transaction::{OutPoint, TxOut},
};
use bitcoin::consensus::encode;
use bitcoin::hashes::Hash;
use bitcoin::network::stream_reader::StreamReader;
use bitcoin::network::{
    address, constants, message,
    message_blockdata::{GetHeadersMessage, Inventory},
    message_filter::{GetCFCheckpt, GetCFHeaders, GetCFilters},
    message_network,
};
use bitcoin::util::bip158::BlockFilter;
use bitcoin::util::hash::BitcoinHash;
use bitcoin::{Address, BlockHash, FilterHash, Network};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json;
use std::fs;
use std::fs::File;
use std::io::BufReader;

mod error;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct UTXO {
    pub outpoint: OutPoint,
    pub txout: TxOut,
}

fn build_version_message(address: SocketAddr) -> message::NetworkMessage {
    // Building version message, see https://en.bitcoin.it/wiki/Protocol_documentation#version
    let my_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);

    // "bitfield of features to be enabled for this connection"
    let services = constants::ServiceFlags::NONE;

    // "standard UNIX timestamp in seconds"
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time error")
        .as_secs();

    // "The network address of the node receiving this message"
    let addr_recv = address::Address::new(&address, constants::ServiceFlags::NONE);

    // "The network address of the node emitting this message"
    let addr_from = address::Address::new(&my_address, constants::ServiceFlags::NONE);

    // "Node random nonce, randomly generated every time a version packet is sent. This nonce is used to detect connections to self."
    let mut rng = rand::thread_rng();
    let nonce: u64 = rng.gen();

    // "User Agent (0x00 if string is 0 bytes long)"
    let user_agent = String::from("rust-example");

    // "The last block received by the emitting node"
    let start_height: i32 = 0;

    // Construct the message
    message::NetworkMessage::Version(message_network::VersionMessage::new(
        services,
        timestamp as i64,
        addr_recv,
        addr_from,
        nonce,
        user_agent,
        start_height,
    ))
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Spv {
    //#[serde(skip)]
    //pub stream: Option<TcpStream>,
    address: Address,
    network: Network,
    peer: SocketAddr,
    pub headers: Vec<BlockHeader>,
    pub checkpoints: Vec<FilterHash>,
    pub filter_headers: Vec<FilterHash>,
    pub filter_height: usize,
    utxos: Vec<UTXO>,
}

impl Spv {
    pub fn new(network: Network, peer: SocketAddr, address: Address) -> Self {
        // FIXME: don'k assume mainnet
        let genesis_header = genesis_block(network).header;
        Self {
            network,
            address,
            peer,
            headers: vec![genesis_header],
            checkpoints: vec![],
            filter_headers: vec![],
            filter_height: 0,
            utxos: vec![],
        }
    }

    pub fn read() -> Result<Self, Error> {
        let start = std::time::Instant::now();
        let file = File::open("db.json")?;
        let reader = BufReader::new(file);
        let db: Self = serde_json::from_reader(reader)?;
        let end = std::time::Instant::now();
        println!("db opened in {:?}", end - start);
        return Ok(db);
    }

    pub fn save(&self) -> Result<(), Error> {
        let path = String::from("db.json");
        let serialized = serde_json::to_string(&self)?;
        fs::write(path, serialized)?;
        Ok(())
    }
    pub fn run(&mut self) {
        //let mut filter_headers: Vec<FilterHash> = vec![FilterHash::from_str(
        //&"0000000000000000000000000000000000000000000000000000000000000000",
        //)
        //.unwrap()];

        // This example establishes a connection to a Bitcoin node, sends the intial
        // "version" message, waits for the reply, and finally closes the connection.
        let mut stream = TcpStream::connect(self.peer).expect("Couldn't establish TCP connection");

        // Start handshake
        let version_message = build_version_message(self.peer);
        self.send_msg(&mut stream, version_message)
            .expect("Couldn't send message");
        println!("Sent version message");

        // Setup StreamReader
        let read_stream = stream.try_clone().unwrap();
        let mut stream_reader = StreamReader::new(read_stream, None);
        loop {
            // Loop an retrieve new messages
            let msg: message::RawNetworkMessage = stream_reader.read_next().unwrap();
            // FIXME: unreachable
            self.handle_msg(&mut stream, msg)
                .expect("Error sending message");
            //let _ = stream.shutdown(Shutdown::Both);
        }
    }
    fn send_msg(
        &self,
        stream: &mut TcpStream,
        payload: message::NetworkMessage,
    ) -> Result<(), Error> {
        let msg = message::RawNetworkMessage {
            magic: self.network.magic(),
            payload,
        };
        stream.write_all(encode::serialize(&msg).as_slice())?;
        Ok(())
    }

    fn handle_msg(
        &mut self,
        stream: &mut TcpStream,
        msg: message::RawNetworkMessage,
    ) -> Result<(), Error> {
        match msg.payload {
            message::NetworkMessage::Version(_) => {
                println!("Received version message: {:?}", msg.payload);
                self.send_msg(stream, message::NetworkMessage::Verack)
                    .expect("couldn't send message");
                println!("Sent verack message");
            }
            message::NetworkMessage::Verack => {
                println!("Received verack message: {:?}", msg.payload);
                let mut locator = vec![];
                for header in self.headers.iter().rev() {
                    locator.push(header.bitcoin_hash());
                    if locator.len() >= 10 {
                        break;
                    }
                }
                let payload = message::NetworkMessage::GetHeaders(GetHeadersMessage::new(
                    locator,
                    BlockHash::default(),
                ));
                self.send_msg(stream, payload)
                    .expect("Couldn't send message");
                println!("Sent getheaders message");
            }
            message::NetworkMessage::Headers(new_block_headers) => {
                println!("received headers: {}", new_block_headers.len());
                //block_headers.append(&mut block_hashes.clone());
                for new_header in &new_block_headers {
                    if let Some(last_header) = self.headers.last() {
                        if last_header.bitcoin_hash() != new_header.prev_blockhash {
                            continue;
                        }
                    } else {
                        let genesis_hash = genesis_block(self.network).bitcoin_hash();
                        assert_eq!(genesis_hash, new_header.bitcoin_hash());
                    }

                    self.headers.push(*new_header);
                }
                if new_block_headers.len() == 2000 {
                    //if self.headers.len() < 10000 {
                    // Send getheaders
                    println!(
                        "Received {} headers, {} total",
                        new_block_headers.len(),
                        self.headers.len()
                    );

                    // FIXME: method
                    let mut locator = vec![];

                    for header in self.headers.iter().rev() {
                        locator.push(header.bitcoin_hash());
                        if locator.len() >= 10 {
                            break;
                        }
                    }

                    let payload = message::NetworkMessage::GetHeaders(GetHeadersMessage::new(
                        locator,
                        BlockHash::default(),
                    ));
                    self.send_msg(stream, payload)
                        .expect("Couldn't send message");
                    println!("Sent getheaders message");
                } else {
                    // Save
                    let start = std::time::Instant::now();
                    //println!("saving db");
                    //self.save().unwrap();
                    //println!("saved db");
                    let end = std::time::Instant::now();
                    println!("Elapsed time saving db: {:?}", end - start);

                    // get filter checkpoints
                    let payload = message::NetworkMessage::GetCFCheckpt(GetCFCheckpt {
                        filter_type: 0,
                        stop_hash: self.headers[self.headers.len() - 1].bitcoin_hash(),
                    });
                    self.send_msg(stream, payload)
                        .expect("Couldn't send message");
                    println!("Sent getcfcheckpt");
                }
            }
            message::NetworkMessage::CFCheckpt(cfcheckpt) => {
                // Save checkpoints
                println!("received cfcheckpt: {:?}", &cfcheckpt);
                for filter_header in cfcheckpt.filter_headers {
                    self.checkpoints.push(filter_header);
                }

                // Get filter headers
                let start_height = 0;
                let stop_hash = self.headers[self.filter_headers.len() + 999].bitcoin_hash();
                let payload = message::NetworkMessage::GetCFHeaders(GetCFHeaders {
                    filter_type: 0,
                    start_height,
                    stop_hash,
                });
                self.send_msg(stream, payload)
                    .expect("Couldn't send message");
            }
            message::NetworkMessage::Block(block) => {
                self.process_block(&block);
            }
            message::NetworkMessage::CFHeaders(cfheaders) => {
                let mut header = cfheaders.previous_filter;
                for filter_hash in cfheaders.filter_hashes.iter() {
                    let mut header_data = [0u8; 64];
                    header_data[0..32].copy_from_slice(&filter_hash[..]);
                    header_data[32..64].copy_from_slice(&header[..]);
                    header = FilterHash::hash(&header_data);
                    if self.filter_headers.len() > 0 && self.filter_headers.len() % 1000 == 0 {
                        let index = (self.filter_headers.len() / 1000) - 1;
                        let checkpoint = self.checkpoints[index];
                        assert_eq!(checkpoint, header);
                    }
                    self.filter_headers.push(header);
                }

                // Get Headers
                let start_height = self.filter_headers.len();
                let stop_height = std::cmp::min(
                    self.filter_headers.len() + 999,
                    //self.headers.len() - self.filter_headers.len(),
                    self.headers.len() - 1,
                );
                if stop_height >= start_height {
                    let stop_hash = self.headers[stop_height].bitcoin_hash();
                    let payload = message::NetworkMessage::GetCFHeaders(GetCFHeaders {
                        filter_type: 0,
                        start_height: start_height as u32,
                        stop_hash,
                    });
                    self.send_msg(stream, payload)
                        .expect("Couldn't send message");
                    println!(
                        "Received cfheaders {:?} {:?}",
                        cfheaders.filter_hashes.len(),
                        self.filter_headers.len()
                    );
                } else {
                    // FIXME: this is a bad heuristic. If we're missing exactly 1000 filter
                    // headers, it will fail.
                    //if self.filter_height >= self.headers.len() {
                    //return Ok(());
                    //}
                    self.request_filter(stream)?;
                    println!("Sent getcfilters");
                }

                // FIXME: download the actual filters and check against the headers
            }
            message::NetworkMessage::CFilter(cfilter) => {
                println!("CFilter: {:?} {}\n\n\n", cfilter, self.filter_height);
                let next_block_hash = self.headers[self.filter_height].bitcoin_hash();

                // Check that
                if next_block_hash != cfilter.block_hash {
                    println!("cfilter doesn't match");
                    println!("filter height: {:?}", self.filter_height);
                    for i in 0..2 {
                        println!("headers {}: {:?}", i, self.headers[i]);
                    }
                    println!("expected: {:?}", next_block_hash);
                    println!("found: {:?}", cfilter.block_hash);
                    self.request_filter(stream)?;
                    //std::thread::sleep_ms(1000);
                    return Ok(());
                }

                // Check against header
                let filter = BlockFilter::new(&cfilter.filter);

                //let filter_hash = FilterHash::hash(filter.content.as_slice()); // Make a method
                let previous_header = if self.filter_height == 0 {
                    FilterHash::from_str(
                        &"0000000000000000000000000000000000000000000000000000000000000000",
                    )
                    .unwrap()
                } else {
                    self.filter_headers[self.filter_height - 1]
                };
                let header = filter.filter_id(&previous_header);

                if self.filter_headers[self.filter_height] != header {
                    println!("filter headers doesn't match at {}", self.filter_height);
                    println!("expected: {:?}", self.filter_headers[self.filter_height]);
                    println!("found: {:?}", header);
                    println!("block hash: {:?}", cfilter.block_hash);
                    return Ok(());
                }

                // TODO: should we check block hash? or is that implied by filter header?

                // Request the full block when it matches our wallet, adjusting filter height when
                // it arrives
                let query = vec![self.address.script_pubkey()];
                let matches =
                    filter.match_any(&cfilter.block_hash, &mut query.iter().map(|s| s.as_bytes()));
                if let Ok(true) = matches {
                    let msg = message::NetworkMessage::GetData(vec![Inventory::Block(
                        cfilter.block_hash.clone(),
                    )]);
                    return self.send_msg(stream, msg);
                } else {
                    // If the block isn't interesting, increment our filter height
                    self.filter_height += 1;
                };

                // Get more filters
                self.request_filter(stream)?;
            }
            _ => {
                println!("Received unknown message: {:?}", msg.cmd());
            }
        };
        Ok(())
    }

    fn request_filter(&mut self, stream: &mut TcpStream) -> Result<(), Error> {
        //let stop_hash = self.headers[self.filter_height + 1].bitcoin_hash();
        if self.headers.len() > self.filter_height {
            let stop_hash = self.headers[self.filter_height].bitcoin_hash();
            println!("requesting {} -> {}", self.filter_height, stop_hash);
            let payload = message::NetworkMessage::GetCFilters(GetCFilters {
                filter_type: 0,
                start_height: self.filter_height as u32,
                // FIXME: why only one?
                stop_hash,
            });
            self.send_msg(stream, payload)
                .expect("Couldn't send message");
        }
        Ok(())
    }

    fn process_block(&mut self, block: &Block) {
        let block_hash = block.bitcoin_hash();
        let expected_hash = self.headers[self.filter_height].bitcoin_hash();
        if block_hash != expected_hash {
            println!("can't process this block yet");
            return;
        }
        // Copying bitcoin-wallet
        for tx in block.txdata.iter() {
            // Just look for outputs for now
            for (vout, output) in tx.output.iter().enumerate() {
                if output.script_pubkey == self.address.script_pubkey() {
                    let outpoint = OutPoint {
                        txid: tx.txid(),
                        vout: vout as u32,
                    };
                    let utxo = UTXO {
                        txout: output.clone(),
                        outpoint,
                    };
                    self.utxos.push(utxo);
                    println!("balance {:?}", self.balance());
                }
            }
        }

        // This filter has been fully processed ...
        self.filter_height += 1;
    }

    fn balance(&self) -> u64 {
        self.utxos.iter().map(|u| u.txout.value).sum()
    }
}

fn exit(msg: &str) {
    eprintln!("{}", msg);
    process::exit(1);
}

fn main() {
    // TODO: parse args here
    let address = Address::from_str("bcrt1qs0wzcfx0ltany6gq43ds3w88kcuxu4umxdrx5u").unwrap();
    let network = Network::Bitcoin;
    let network = Network::Regtest;

    // Parse CLI
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        exit("usage: spv <mainnet|regtest|testnet> <peer-ip> <bitcoin-address>");
    }

    let network = match &args[1][..] {
        "mainnet" => Network::Bitcoin,
        "testnet" => Network::Testnet,
        "regtest" => Network::Regtest,
        _ => {
            eprintln!("usage: spv <mainnet|regtest|testnet> <peer-ip> <bitcoin-address>");
            process::exit(1);
        }
    };

    let peer: SocketAddr = args[2].parse().unwrap_or_else(|error| {
        eprintln!("Error parsing peer address: {:?}", error);
        process::exit(1);
    });

    let address: Address = args[3].parse().unwrap_or_else(|error| {
        eprintln!("Error parsing bitcoin address: {:?}", error);
        process::exit(1);
    });

    let mut spv = Spv::new(network, peer, address);
    spv.run();
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::encode::deserialize;
    use bitcoin::{Address, BlockHeader};
    use hex::decode as hex_decode;

    #[test]
    fn simple_test() {
        let raw = hex_decode("010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914cd74d6e49ffff001d323b3a7b").unwrap();

        let header: BlockHeader =
            deserialize(&raw).expect("Can't deserialize correct block header");

        // FIXME: this is weird
        let address = Address::from_str("bcrt1qs0wzcfx0ltany6gq43ds3w88kcuxu4umxdrx5u").unwrap();
        let spv = Spv::new(Network::Regtest, address);
        spv.headers = vec![header, header, header];

        spv.save().unwrap();
        let from_disk = Spv::read().unwrap();
        assert_eq!(spv, from_disk);
    }

    #[test]
    fn test_block_filter() {
        // or create a filter from known raw data
        let filter = BlockFilter::new(&hex_decode("01494ac0").unwrap());

        // read and evaluate a filter
        let block_hash =
            BlockHash::from_str("4f4dbdc4f62f3cf13db071e70f7eba5c36b7b1334bf68c1e69b7f76ae10003d0")
                .unwrap();
        let address = Address::from_str("bcrt1qs0wzcfx0ltany6gq43ds3w88kcuxu4umxdrx5u").unwrap();
        //let query: Iterator<Item = Script> = vec![address.script_pubkey()];
        let query = vec![address.script_pubkey()];
        let matches = filter
            .match_any(&block_hash, &mut query.iter().map(|s| s.as_bytes()))
            .unwrap();
        assert!(matches);

        let address = Address::from_str("bcrt1qdwasrapfa8xdumgeg4pgujl94lug570t7a6f8m").unwrap();
        //let query: Iterator<Item = Script> = vec![address.script_pubkey()];
        let query = vec![address.script_pubkey()];
        let matches = filter
            .match_any(&block_hash, &mut query.iter().map(|s| s.as_bytes()))
            .unwrap();
        assert!(!matches);
    }

    fn test_regtest() {}
}

#[cfg(test)]
mod rpc_test {
    use super::*;
    use crate::descriptor::*;
    use crate::{sled, Wallet};
    use bitcoin::util::bip32::ExtendedPrivKey;
    use bitcoin::{Amount, Network};
    use bitcoincore_rpc::{Auth, Client};
    use dirs::home_dir;

    use std::str::FromStr;

    use rand::distributions::Alphanumeric;
    use rand::{thread_rng, Rng, RngCore};

    fn rand_str() -> String {
        thread_rng().sample_iter(&Alphanumeric).take(10).collect()
    }

    fn make_descriptors() -> (String, String) {
        let mut seed = vec![0u8; 16];
        thread_rng().fill_bytes(seed.as_mut_slice());

        let network = Network::Bitcoin;
        let sk = ExtendedPrivKey::new_master(network, &seed).unwrap();
        let external = format!("wpkh({}/0/*)", sk.to_string());
        let internal = format!("wpkh({}/1/*)", sk.to_string());
        (external, internal)
    }

    fn test_rpc_sync() {
        // Create a random wallet name
        let wallet_name = rand_str();

        // Create blockchain client
        let wallet_url = String::from(format!("http://127.0.0.1:18443/wallet/{}", wallet_name));
        let default_url = String::from("http://127.0.0.1:18443/wallet/");
        let path = std::path::PathBuf::from(format!(
            "{}/.bitcoin/regtest/.cookie",
            home_dir().unwrap().to_str().unwrap()
        ));
        let auth = Auth::CookieFile(path);
        let wallet_client = Client::new(wallet_url.clone(), auth.clone()).unwrap();
        let default_client = Client::new(default_url, auth.clone()).unwrap();

        // Create watch-only wallet
        default_client
            .create_wallet(&wallet_name, Some(true))
            .unwrap();

        // Mine 150 blocks to default wallet
        let default_addr = default_client.get_new_address(None, None).unwrap();
        default_client
            .generate_to_address(150, &default_addr)
            .unwrap();

        // Send 1 BTC to each of first 21 wallet addresses, so that we need multiple
        // listtransactions calls
        let (desc_ext, desc_int) = make_descriptors();
        let extended = ExtendedDescriptor::from_str(&desc_ext).unwrap();
        for index in 0..21 {
            let derived = extended.derive(index).unwrap();
            let address = derived.address(Network::Regtest).unwrap();
            let amount = Amount::from_btc(1.0).unwrap();
            default_client
                .send_to_address(&address, amount, None, None, None, None, None, None)
                .unwrap();
        }

        // Mine another block so ^^ are confirmed
        default_client
            .generate_to_address(1, &default_addr)
            .unwrap();

        // Sync the wallet
        let wallet = Wallet::new(
            &desc_ext,
            Some(&desc_int),
            Network::Regtest,
            tree.clone(),
            blockchain,
        )
        .await
        .unwrap();
        wallet.sync(None, None).await.unwrap();

        // Check that RPC and database show same transactions
        let wallet_txs = wallet.list_transactions(false).unwrap();
        assert_eq!(21, wallet_txs.len());

        // Check unspents
        let wallet_unspent = wallet.list_unspent().unwrap();
        assert_eq!(21, wallet_unspent.len());

        // Check balances
        let wallet_client = Client::new(wallet_url, auth.clone()).unwrap();
        let wallet_balance = Amount::from_sat(wallet.get_balance().unwrap());
        let rpc_balance = wallet_client.get_balance(None, Some(true)).unwrap();
        assert_eq!(wallet_balance, rpc_balance);

        // Spend one utxo back to default wallet, mine a block, sync wallet
        let (psbt, _) = wallet
            .create_tx(
                vec![(default_addr.clone(), 100000000)],
                false,
                1.0 * 1e-5,
                None,
                None,
                None,
            )
            .unwrap();
        let (psbt, _) = wallet.sign(psbt, None).unwrap();
        let tx = psbt.extract_tx();
        wallet.broadcast(tx.clone()).await.unwrap();
        default_client
            .generate_to_address(1, &default_addr)
            .unwrap();
        wallet.sync(None, None).await.unwrap();

        // One more transaction, one less utxo
        assert_eq!(22, wallet.list_transactions(false).unwrap().len());
        assert_eq!(20, wallet.list_unspent().unwrap().len());

        let input_amount: u64 = tx
            .input
            .iter()
            .map(|i| {
                tree.get_previous_output(&i.previous_output)
                    .unwrap()
                    .unwrap()
                    .value
            })
            .sum();
        let output_amount: u64 = tx.output.iter().map(|o| o.value as u64).sum();
        let fee = input_amount - output_amount;
        assert_eq!(
            wallet_balance - Amount::from_btc(1.0).unwrap() - Amount::from_sat(fee),
            Amount::from_sat(wallet.get_balance().unwrap())
        );

        // generate an address
        // fund that address
        // check the balance
        // sweep that address
        // check the balance

        // missing pieces
        // 1. run in thread and still access balances
        // 2. check block filter against list of script pubkeys
        // 3. requests blocks that match
        // 4. handle block messages
        // 5. save balances somewhere
    }
}
