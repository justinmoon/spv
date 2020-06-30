extern crate bitcoin;

use core::str::FromStr;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpStream};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, process};

use bitcoin::blockdata::block::BlockHeader;
use bitcoin::consensus::encode;
use bitcoin::network::stream_reader::StreamReader;
use bitcoin::network::{
    address, constants, message,
    message_blockdata::GetHeadersMessage,
    message_filter::{CFCheckpt, GetCFCheckpt, GetCFHeaders, GetCFilters},
    message_network,
};
use bitcoin::util::hash::BitcoinHash;
use bitcoin::{BlockHash, FilterHash};

use bitcoin_hashes::sha256d::Hash as Sha256dHash;

use rand::Rng;

pub fn run() {
    let mut block_headers: Vec<BlockHeader> = vec![];
    let mut checkpoints: Vec<FilterHash> = vec![];
    let mut filter_hashes: Vec<FilterHash> = vec![];

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
                    let start_height = 1;
                    let stop_hash = BlockHash::from_str(
                        // block 1000
                        &"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09",
                        //&"00000000a2887344f8db859e372e7e4bc26b23b9de340f725afbf2edb265b4c6",
                    )
                    .unwrap();
                    let payload = message::NetworkMessage::GetCFilters(GetCFilters {
                        filter_type: 0,
                        start_height: 1000,
                        stop_hash,
                    });
                    let msg = message::RawNetworkMessage {
                        magic: constants::Network::Bitcoin.magic(),
                        payload,
                    };
                    let _ = stream.write_all(encode::serialize(&msg).as_slice());

                    let payload = message::NetworkMessage::GetCFHeaders(GetCFHeaders {
                        filter_type: 0,
                        start_height: 1000,
                        stop_hash,
                    });
                    let msg = message::RawNetworkMessage {
                        magic: constants::Network::Bitcoin.magic(),
                        payload,
                    };
                    let _ = stream.write_all(encode::serialize(&msg).as_slice());
                }
                message::NetworkMessage::CFHeaders(cfheaders) => {
                    println!("CFHeaders: {:?}", cfheaders);
                    println!("CFHeaders.len: {:?}", cfheaders.filter_hashes.len());
                }
                message::NetworkMessage::CFilter(cfilter) => {
                    println!("CFilter: {:?}", cfilter);
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
