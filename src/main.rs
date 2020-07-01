extern crate bitcoin;

use core::str::FromStr;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpStream};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, process};

use bitcoin::blockdata::block::BlockHeader;
use bitcoin::consensus::encode;
use bitcoin::network::stream_reader::StreamReader;
use bitcoin::network::{
    address, constants, message, message_blockdata::GetHeadersMessage, message_network,
};
use bitcoin::util::hash::BitcoinHash;
use bitcoin::BlockHash;

use bitcoin_hashes::sha256d::Hash as Sha256dHash;

use rand::Rng;

pub mod checkpoints;
pub mod error;
pub mod io;
pub mod lookup;

fn headers() {
    let mut header_chain: Vec<BlockHeader> = vec![];

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
                    let locator = vec![genesis.clone().into()];
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
                message::NetworkMessage::Headers(block_hashes) => {
                    header_chain.append(&mut block_hashes.clone());
                    let mut locator = vec![];

                    for header in header_chain.iter().rev() {
                        locator.push(header.bitcoin_hash());
                        if locator.len() >= 10 {
                            break;
                        }
                    }

                    //let locator = header_chain.iter().rev().take(10).collect();
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
                        block_hashes.len(),
                        header_chain.len()
                    );
                    println!("Sent getheaders message");
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

fn main() {
    checkpoints::run();
}
