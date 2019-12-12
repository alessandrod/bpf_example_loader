use std::env;
use std::path::PathBuf;
use std::io;
use std::net::IpAddr;
use futures::stream::StreamExt;
use tokio;
use tokio::runtime::Runtime;
use tokio::signal;
use redbpf::load::Loader;
use redbpf::XdpFlags;

use bpf_examples::trace_http::{MapData, RequestInfo};

#[tokio::main]
async fn main() -> Result<(), io::Error> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: bpf_example_program [NETWORK_INTERFACE] [FILENAME]");
        return Err(io::Error::new(io::ErrorKind::Other, "invalid arguments"));
    }
    let interface = args[1].clone();
    let file = args[2].clone();
    let mut loader = Loader::new()
        .xdp(Some(interface), XdpFlags::default())
        .load_file(&file.into())
        .await
        .expect("error loading file");
    tokio::spawn(async move {
        while let Some((_, events)) = loader.events.next().await {
            for event in events {
                let event = unsafe { &*(event.as_ptr() as *const MapData<RequestInfo>) };
                let info = &event.data;
                let payload = String::from_utf8_lossy(event.payload());
                let req_line = payload.split("\r\n").next().unwrap();
                let ip = IpAddr::from(info.saddr.to_ne_bytes());
                println!("{} - {}", ip, req_line);
            }
        }
    });

    signal::ctrl_c().await
}