extern crate bitcoin;

use core::str::FromStr;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpStream};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, process};

use bitcoin::blockdata::block::BlockHeader;
use bitcoin::consensus::encode;
use bitcoin::hashes::Hash;
use bitcoin::network::stream_reader::StreamReader;
use bitcoin::network::{
    address, constants, message,
    message_blockdata::GetHeadersMessage,
    message_filter::{CFCheckpt, GetCFCheckpt, GetCFHeaders, GetCFilters},
    message_network,
};
use bitcoin::util::bip158::BlockFilter;
use bitcoin::util::hash::BitcoinHash;
use bitcoin::{BlockHash, FilterHash};

use bitcoin_hashes::sha256d::Hash as Sha256dHash;

use rand::Rng;

pub fn run() {
    let mut block_headers: Vec<BlockHeader> = vec![];
    let mut checkpoints: Vec<FilterHash> = vec![];
    let mut filter_headers: Vec<FilterHash> = vec![];
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

    let version_message = build_version_message(address);

    let first_message = message::RawNetworkMessage {
        magic: constants::Network::Bitcoin.magic(),
        payload: version_message,
    };

    if let Ok(mut stream) = TcpStream::connect(address) {
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
                    let genesis = Sha256dHash::from_str(
                        &"000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
                    )
                    .unwrap();
                    //let locator = vec![genesis.clone().into()];
                    let locator = vec![];
                    let payload = message::NetworkMessage::GetHeaders(GetHeadersMessage::new(
                        locator,
                        genesis.into(),
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
                        if let Some(last_header) = block_headers.last() {
                            assert_eq!(last_header.bitcoin_hash(), new_header.prev_blockhash);
                        } else {
                            let genesis = BlockHash::from_str(
                                &"000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
                            )
                            .unwrap();
                            assert_eq!(genesis, new_header.bitcoin_hash());
                        }

                        block_headers.push(*new_header);
                    }
                    //if new_block_headers.len() == 2000 {
                    if block_headers.len() < 10000 {
                        // Send getheaders
                        let mut locator = vec![];

                        for header in block_headers.iter().rev() {
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
                            block_headers.len()
                        );
                        println!("Sent getheaders message");
                    } else {
                        // get filter checkpoints
                        let payload = GetCFCheckpt {
                            filter_type: 0,
                            stop_hash: block_headers[block_headers.len() - 1].bitcoin_hash(),
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
                        checkpoints.push(filter_header);
                    }

                    // Get Headers
                    let start_height = 0;
                    let stop_hash = block_headers[filter_headers.len() + 999].bitcoin_hash();
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
                        if filter_headers.len() > 0 && filter_headers.len() % 1000 == 0 {
                            let index = (filter_headers.len() / 1000) - 1;
                            let checkpoint = checkpoints[index];
                            assert_eq!(checkpoint, header);
                        }
                        filter_headers.push(header);
                    }

                    // Get Headers
                    let start_height = filter_headers.len();
                    let stop_height = std::cmp::min(
                        filter_headers.len() + 999,
                        block_headers.len() - filter_headers.len(),
                    );
                    let stop_hash = block_headers[stop_height].bitcoin_hash();
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
                        filter_headers.len()
                    );

                    //if stop_height < 1000 {
                    // Get Filters
                    let payload = message::NetworkMessage::GetCFilters(GetCFilters {
                        filter_type: 0,
                        start_height: 0,
                        stop_hash: block_headers[1].bitcoin_hash(),
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
                    let next_block_hash = block_headers[next_height].bitcoin_hash();

                    // Check that
                    if next_block_hash != cfilter.block_hash {
                        println!("cfilter doesn't match");
                        println!("filters.len() {}", filters.len());
                        println!("height: {:?}", next_height);
                        for i in 0..2 {
                            println!("headers {}: {:?}", i, block_headers[i]);
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
                        filter_headers[next_height - 1]
                    };
                    let header = filter.filter_id(&previous_header);

                    if filter_headers[next_height] != header {
                        println!("filter headers doesn't match at {}", next_height);
                        println!("expected: {:?}", filter_headers[next_height]);
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
                        stop_hash: block_headers[next_height + 1].bitcoin_hash(),
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
        let _ = stream.shutdown(Shutdown::Both);
    } else {
        eprintln!("Failed to open connection");
    }
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
