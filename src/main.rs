use http::uri::Uri;
use std::io::{prelude::*, stdin};
use std::path::PathBuf;
mod lib;
use std::sync::{Arc, Mutex};

fn main() {
    let mut bindings = lib::FunctionBindings::new();
    let times_called = Arc::new(Mutex::new(0));
    bindings.bind(String::from("/test"), move |buffer, uri| {
        let mut tc = times_called.lock().unwrap();
        *tc += 1;

        buffer.extend(
            format!(
                "<h1>Welcome to my site!</h1> You are calling: {} For the {} time.",
                uri, &tc
            )
            .as_bytes(),
        );

        ("text/html", false)
    });
    let config = lib::config::server_config::get_server_config("cert.pem", "privkey.pem")
        .expect("Failed to read certificate!");
    let server = lib::Config::new(config, bindings, 443);
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
                        let mut fc = fc.lock().unwrap();
                        fc.clear();
                        println!("Cleared file system cache!");
                    }
                    "cc" => {
                        let mut rc = rc.lock().unwrap();
                        let mut fc = fc.lock().unwrap();
                        rc.clear();
                        fc.clear();
                        println!("Cleared all caches!");
                    }
                    _ => {
                        eprintln!("Unknown command!");
                    }
                }
            }
        };
    }
}
