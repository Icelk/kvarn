use arktis;
use http::uri::Uri;
use std::io::{prelude::*, stdin};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;

fn main() {
    let mut bindings = arktis::FunctionBindings::new();
    let times_called = Arc::new(Mutex::new(0));
    bindings.bind("/test", move |buffer, request| {
        let mut tc = times_called.lock().unwrap();
        *tc += 1;

        buffer.extend(
            format!(
                "<h1>Welcome to my site!</h1> You are calling: {} For the {} time.",
                request.uri(),
                &tc
            )
            .as_bytes(),
        );

        ("text/html", false)
    });
    bindings.bind("/throw_500", |mut buffer, _| {
        arktis::write_generic_error(&mut buffer, 500).expect("Failed to write to Vec!?");

        ("text/html", false)
    });
    bindings.bind_dir("/capturing", |buffer, request| {
        buffer.extend(
            b"<h1>Hi!</h1>This entire root directory is captured by a function. You are visiting '"
                .iter(),
        );
        buffer.extend(
            request
                .uri()
                .path_and_query()
                .and_then(|path| Some(path.as_str()))
                .unwrap_or("/")
                .as_bytes(),
        );
        buffer.extend(b"' right? :-)<br>Well, hope you enjoy <a href=\"/\">this site!</a>".iter());

        ("text/html", true)
    });
    let server = arktis::Config::with_bindings(bindings, 443);
    let mut cache = server.clone_cache();
    thread::spawn(move || server.run());

    for line in stdin().lock().lines() {
        if let Ok(line) = line {
            let mut words = line.split(" ");
            if let Some(command) = words.next() {
                match command {
                    "rcc" => {
                        // Responds cache clear
                        let mut rc = cache.mut_response().lock().unwrap();
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
                        let mut fc = cache.mut_fs().lock().unwrap();
                        let path = PathBuf::from(words.next().unwrap_or(&""));
                        match fc.remove(&path) {
                            Some(..) => println!("Removed item from cache!"),
                            None => println!("No item to remove"),
                        };
                    }
                    "crc" => {
                        let mut rc = cache.mut_response().lock().unwrap();
                        rc.clear();
                        println!("Cleared response cache!");
                    }
                    "cfc" => {
                        let mut fc = cache.mut_fs().lock().unwrap();
                        fc.clear();
                        println!("Cleared file system cache!");
                    }
                    "cc" => {
                        cache.clear();
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
