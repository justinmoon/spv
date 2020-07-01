use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, process};

use bitcoin::consensus::encode;
use bitcoin::hashes::Hash;
use bitcoin::network::stream_reader::StreamReader;
use bitcoin::network::{
    address, constants, message,
    message_blockdata::GetHeadersMessage,
    message_filter::{GetCFCheckpt, GetCFHeaders, GetCFilters},
    message_network,
};
use bitcoin::util::bip158::BlockFilter;
use bitcoin::util::hash::BitcoinHash;
use bitcoin::{BlockHash, FilterHash};
use rand::Rng;

mod error;
mod io;

use crate::io::Db;

pub fn main() {
    let mut db = Db::new();
    let mut filters: Vec<BlockFilter> = vec![];

    //let mut filter_headers: Vec<FilterHash> = vec![FilterHash::from_str(
    //&"0000000000000000000000000000000000000000000000000000000000000000",
    //)
    //.unwrap()];

    // This example establishes a connection to a Bitcoin node, sends the intial
    // "version" message, waits for the reply, and finally closes the connection.
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("not enough arguments");
        process::exit(1);
    }

    let str_address = &args[1];

    let address: SocketAddr = str_address.parse().unwrap_or_else(|error| {
        eprintln!("Error parsing address: {:?}", error);
        process::exit(1);
    });

    println!("starting");
    let version_message = build_version_message(address);

    let first_message = message::RawNetworkMessage {
        magic: constants::Network::Bitcoin.magic(),
        payload: version_message,
    };

    let mut stream = TcpStream::connect(address).expect("Couldn't establish TCP connection");
    // Send the message
    let _ = stream.write_all(encode::serialize(&first_message).as_slice());
    println!("Sent version message");

    // Setup StreamReader
    let read_stream = stream.try_clone().unwrap();
    let mut stream_reader = StreamReader::new(read_stream, None);
    loop {
        // Loop an retrieve new messages
        let reply: message::RawNetworkMessage = stream_reader.read_next().unwrap();
        match reply.payload {
            message::NetworkMessage::Version(_) => {
                println!("Received version message: {:?}", reply.payload);

                let second_message = message::RawNetworkMessage {
                    magic: constants::Network::Bitcoin.magic(),
                    payload: message::NetworkMessage::Verack,
                };

                let _ = stream.write_all(encode::serialize(&second_message).as_slice());
                println!("Sent verack message");
            }
            message::NetworkMessage::Verack => {
                println!("Received verack message: {:?}", reply.payload);
                let mut locator = vec![];
                for header in db.headers.iter().rev() {
                    locator.push(header.bitcoin_hash());
                    if locator.len() >= 10 {
                        break;
                    }
                }
                let payload = message::NetworkMessage::GetHeaders(GetHeadersMessage::new(
                    locator,
                    BlockHash::default(),
                ));
                let msg = message::RawNetworkMessage {
                    magic: constants::Network::Bitcoin.magic(),
                    payload,
                };
                let _ = stream.write_all(encode::serialize(&msg).as_slice());
                println!("Sent getheaders message");
            }
            message::NetworkMessage::Headers(new_block_headers) => {
                //block_headers.append(&mut block_hashes.clone());
                for new_header in &new_block_headers {
                    if let Some(last_header) = db.headers.last() {
                        if last_header.bitcoin_hash() != new_header.prev_blockhash {
                            continue;
                        }
                    } else {
                        let genesis = BlockHash::from_str(
                            &"000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
                        )
                        .unwrap();
                        assert_eq!(genesis, new_header.bitcoin_hash());
                    }

                    db.headers.push(*new_header);
                }
                if new_block_headers.len() == 2000 {
                    //if db.headers.len() < 10000 {
                    // Send getheaders
                    let mut locator = vec![];

                    for header in db.headers.iter().rev() {
                        locator.push(header.bitcoin_hash());
                        if locator.len() >= 10 {
                            break;
                        }
                    }

                    let payload = message::NetworkMessage::GetHeaders(GetHeadersMessage::new(
                        locator,
                        BlockHash::default(),
                    ));
                    let msg = message::RawNetworkMessage {
                        magic: constants::Network::Bitcoin.magic(),
                        payload,
                    };
                    let _ = stream.write_all(encode::serialize(&msg).as_slice());
                    println!(
                        "Received {} headers, {} total",
                        new_block_headers.len(),
                        db.headers.len()
                    );
                    println!("Sent getheaders message");
                } else {
                    // Save
                    let start = std::time::Instant::now();
                    println!("saving db");
                    db.save().unwrap();
                    println!("saved db");
                    let end = std::time::Instant::now();
                    println!("Elapsed time saving db: {:?}", end - start);

                    // get filter checkpoints
                    let payload = GetCFCheckpt {
                        filter_type: 0,
                        stop_hash: db.headers[db.headers.len() - 1].bitcoin_hash(),
                    };
                    let msg = message::RawNetworkMessage {
                        magic: constants::Network::Bitcoin.magic(),
                        payload: message::NetworkMessage::GetCFCheckpt(payload),
                    };
                    let _ = stream.write_all(encode::serialize(&msg).as_slice());
                    println!("Sent getcfcheckpt");
                }
            }
            message::NetworkMessage::CFCheckpt(cfcheckpt) => {
                // Save checkpoints
                println!("received cfcheckpt: {:?}", &cfcheckpt);
                for filter_header in cfcheckpt.filter_headers {
                    db.checkpoints.push(filter_header);
                }

                // Get Headers
                let start_height = 0;
                println!("{}", db.headers.len());
                let stop_hash = db.headers[db.filter_headers.len() + 999].bitcoin_hash();
                let payload = message::NetworkMessage::GetCFHeaders(GetCFHeaders {
                    filter_type: 0,
                    start_height,
                    stop_hash,
                });
                let msg = message::RawNetworkMessage {
                    magic: constants::Network::Bitcoin.magic(),
                    payload,
                };
                let _ = stream.write_all(encode::serialize(&msg).as_slice());
            }
            message::NetworkMessage::CFHeaders(cfheaders) => {
                let mut header = cfheaders.previous_filter;
                for filter_hash in cfheaders.filter_hashes.iter() {
                    let mut header_data = [0u8; 64];
                    header_data[0..32].copy_from_slice(&filter_hash[..]);
                    header_data[32..64].copy_from_slice(&header[..]);
                    header = FilterHash::hash(&header_data);
                    if db.filter_headers.len() > 0 && db.filter_headers.len() % 1000 == 0 {
                        let index = (db.filter_headers.len() / 1000) - 1;
                        let checkpoint = db.checkpoints[index];
                        assert_eq!(checkpoint, header);
                    }
                    db.filter_headers.push(header);
                }

                // Get Headers
                let start_height = db.filter_headers.len();
                let stop_height = std::cmp::min(
                    db.filter_headers.len() + 999,
                    db.headers.len() - db.filter_headers.len(),
                );
                let stop_hash = db.headers[stop_height].bitcoin_hash();
                let payload = message::NetworkMessage::GetCFHeaders(GetCFHeaders {
                    filter_type: 0,
                    start_height: start_height as u32,
                    stop_hash,
                });
                let msg = message::RawNetworkMessage {
                    magic: constants::Network::Bitcoin.magic(),
                    payload,
                };
                let _ = stream.write_all(encode::serialize(&msg).as_slice());
                println!(
                    "Received cfheaders {:?} {:?}",
                    cfheaders.filter_hashes.len(),
                    db.filter_headers.len()
                );

                //if stop_height < 1000 {
                // Get Filters
                let start_height = db.filter_headers.len();
                if start_height >= db.headers.len() {
                    continue;
                }
                let stop_hash = db.headers[start_height].bitcoin_hash();
                let payload = message::NetworkMessage::GetCFilters(GetCFilters {
                    filter_type: 0,
                    start_height: start_height as u32,
                    stop_hash,
                });
                let msg = message::RawNetworkMessage {
                    magic: constants::Network::Bitcoin.magic(),
                    payload,
                };
                let _ = stream.write_all(encode::serialize(&msg).as_slice());
                println!("Sent getcfilters");
                //}

                // FIXME: download the actual filters and check against the headers
            }
            message::NetworkMessage::CFilter(cfilter) => {
                println!("CFilter: {:?}\n\n\n", cfilter);
                let next_height = filters.len();
                let current_height = std::cmp::max(next_height, 0);
                let next_block_hash = db.headers[next_height].bitcoin_hash();

                // Check that
                if next_block_hash != cfilter.block_hash {
                    println!("cfilter doesn't match");
                    println!("filters.len() {}", filters.len());
                    println!("height: {:?}", next_height);
                    for i in 0..2 {
                        println!("headers {}: {:?}", i, db.headers[i]);
                    }
                    println!("expected: {:?}", next_block_hash);
                    println!("found: {:?}", cfilter.block_hash);
                    continue;
                }

                // Check against header
                let filter = BlockFilter::new(&cfilter.filter);
                //let filter_hash = FilterHash::hash(filter.content.as_slice()); // Make a method
                let previous_header = if current_height == 0 {
                    FilterHash::from_str(
                        &"0000000000000000000000000000000000000000000000000000000000000000",
                    )
                    .unwrap()
                } else {
                    db.filter_headers[next_height - 1]
                };
                let header = filter.filter_id(&previous_header);

                if db.filter_headers[next_height] != header {
                    println!("filter headers doesn't match at {}", next_height);
                    println!("expected: {:?}", db.filter_headers[next_height]);
                    println!("found: {:?}", header);
                    println!("block hash: {:?}", cfilter.block_hash);
                    continue;
                }

                // Save the filter
                filters.push(filter);

                // Get more filters
                let payload = message::NetworkMessage::GetCFilters(GetCFilters {
                    filter_type: 0,
                    start_height: next_height as u32,
                    stop_hash: db.headers[next_height + 1].bitcoin_hash(),
                });
                let msg = message::RawNetworkMessage {
                    magic: constants::Network::Bitcoin.magic(),
                    payload,
                };
                let _ = stream.write_all(encode::serialize(&msg).as_slice());
            }
            _ => {
                println!("Received unknown message: {:?}", reply.cmd());
            }
        }
    }
    // FIXME: unreachable
    //let _ = stream.shutdown(Shutdown::Both);
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

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::encode::deserialize;
    use bitcoin::{Address, BlockHeader, Script};
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
