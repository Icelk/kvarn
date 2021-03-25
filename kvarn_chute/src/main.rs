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

    const HEADER_PRE_META: &[u8] = b"!> tmpl standard.html markdown.html\n[head]";
    const HEADER_POST_META: &[u8] =
        b"[dependencies][md-imports][close-head][navigation]\n<main><md>";
    const FOOTER: &[u8] = b"</md></main>\n[footer]\n";
    const IGNORED_EXTENSIONS: &[&str] = &["hide"];

    match path.is_dir() {
        true => {
            println!("Watching directory and overriding files.");
            lib::watch(
                &path,
                HEADER_PRE_META,
                HEADER_POST_META,
                FOOTER,
                IGNORED_EXTENSIONS,
            )
            .unwrap();
        }
        false => match lib::process_document(
            &path,
            HEADER_PRE_META,
            HEADER_POST_META,
            FOOTER,
            IGNORED_EXTENSIONS,
            false,
        ) {
            Ok(()) => lib::wait_for("Press enter to close..."),
            Err(ref err) if err.kind() == io::ErrorKind::PermissionDenied => {
                lib::exit_with_message("You do not have permission to read the file specified.");
            }
            Err(_) => lib::exit_with_message("Failed to write to output file."),
        },
    }
}
