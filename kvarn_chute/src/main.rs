use std::{env, io, io::Read};
pub mod lib;

fn main() {
    println!("Starting Kvarn Markdown to Html converter.");
    let mut args = env::args();
    args.next();
    let file = match args.next() {
        Some(path) => path,
        None => lib::exit_with_message("Please enter a filepath as the first argument."),
    };
    if let Err(_) = lib::process_document(
        file,
        b"!> tmpl standard markdown\n[head]\n[dependencies]\n[close-head]\n[navbar]\n<main style=\"text-align: center;\">",
        b"</main>[footer]\n",
        &["hide"]
    ){
        lib::exit_with_message("Failed to write to output file.");
    }
    println!("Press enter to close...");
    let _ = io::stdin().read(&mut [0; 0]);
}
