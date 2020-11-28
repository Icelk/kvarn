use std::{env, io, path::PathBuf};
pub mod lib;

fn main() {
    println!("Starting Kvarn Markdown to Html converter.");
    let mut args = env::args();
    args.next();
    let path = match args.next() {
        Some(path) => PathBuf::from(path),
        None => lib::exit_with_message(
            "Please enter a path to a file to convert or directory to watch as the first argument.",
        ),
    };

    const HEADER: &[u8] = b"!> tmpl standard markdown\n[head][md-title][dependencies][md-imports][close-head][navbar]\n<main><md style=\"text-align: center;\">";
    const FOOTER: &[u8] = b"</md></main>\n[footer]\n";
    const IGNORED_EXTENSIONS: &[&str] = &["hide"];

    match lib::process_document(&path, HEADER, FOOTER, IGNORED_EXTENSIONS, false) {
        Ok(()) => lib::wait_for("Press enter to close..."),
        Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {
            // Check if dir!
            let metadata = path.metadata();
            if metadata.is_ok() && metadata.as_ref().unwrap().is_dir() {
                // let metadata = metadata.unwrap();
                println!("Watching directory and overriding files.");
                lib::watch(&path, HEADER, FOOTER, IGNORED_EXTENSIONS).unwrap();
            } else {
                lib::exit_with_message("You do not have permission to read the file specified.");
            }
        }
        Err(_) => lib::exit_with_message("Failed to write to output file."),
    }
}
