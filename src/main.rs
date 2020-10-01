use http::uri::{self, Uri};
use std::io::{prelude::*, stdin};
use std::net::TcpListener;
use std::path::PathBuf;
mod lib;

fn main() {
    let listener = TcpListener::bind("0.0.0.0:443").unwrap();

    let server_config = lib::get_config("cert.pem", "privkey.pem").unwrap();

    let (fc, rc) = lib::run(listener, server_config).expect("Failed to run server!");

    for line in stdin().lock().lines() {
        if let Ok(line) = line {
            let mut words = line.split(" ");
            if let Some(command) = words.next() {
                match command {
                    "rcc" => {
                        // Responds cache clear
                        let mut rc = rc.lock().unwrap();
                        let uri = match Uri::builder()
                            .path_and_query(words.next().unwrap_or(&""))
                            .build()
                        {
                            Ok(uri) => uri,
                            Err(..) => {
                                eprintln!("Failed to format path");
                                continue;
                            }
                        };
                        match rc.remove(&uri) {
                            Some(..) => println!("Removed item from cache!"),
                            None => println!("No item to remove"),
                        };
                    }
                    "fcc" => {
                        // File cache clear
                        let mut fc = fc.lock().unwrap();
                        let path = /* match */ PathBuf::from(words.next().unwrap_or(&""))/* 
                        {
                            Ok(path) => path,
                            Err(..) => eprintln!("Failed to format path"),
                        } */;
                        match fc.remove(&path) {
                            Some(..) => println!("Removed item from cache!"),
                            None => println!("No item to remove"),
                        };
                    }
                    _ => {
                        println!("Unknown command!");
                    }
                }
            }
        };
    }
}
