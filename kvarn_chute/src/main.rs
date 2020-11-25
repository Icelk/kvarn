use std::env;
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
        b"!> tmpl standard markdown\n[head][md-title][dependencies][md-imports][close-head][navbar]\n<main style=\"text-align: center;\">",
        b"</main>\n[footer]\n",
        &["hide"]
    ){
        lib::exit_with_message("Failed to write to output file.");
    }
    lib::wait_for("Press enter to close...");
}
