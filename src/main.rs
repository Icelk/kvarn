use http::uri::Uri;
use std::io::{prelude::*, stdin};
use std::path::PathBuf;
mod lib;

fn main() {
    let server = lib::Config::on_port(443);
    let fc = server.get_fs_cache();
    let rc = server.get_response_cache();
    server.run();

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
                        let path = PathBuf::from(words.next().unwrap_or(&""));
                        match fc.remove(&path) {
                            Some(..) => println!("Removed item from cache!"),
                            None => println!("No item to remove"),
                        };
                    }
                    "crc" => {
                        let mut rc = rc.lock().unwrap();
                        rc.clear();
                        println!("Cleared response cache!");
                    }
                    "cfc" => {
                        let mut rc = rc.lock().unwrap();
                        rc.clear();
                        println!("Cleared file system cache!");
                    }
                    _ => {
                        println!("Unknown command!");
                    }
                }
            }
        };
    }
}
