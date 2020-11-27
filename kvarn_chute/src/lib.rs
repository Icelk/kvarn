use pulldown_cmark::{html, Options, Parser};
use std::io::{self, prelude::*};
use std::path::Path;

/// ToDo: Remove this, and import from Kvarn Core or Kvarn Kärna
pub(crate) mod parse {

    pub mod chars {
        /// Line feed
        pub const LF: u8 = 10;
        /// Carrage return
        pub const CR: u8 = 13;
        /// ` `
        pub const SPACE: u8 = 32;
        /// `!`
        pub const BANG: u8 = 33;
        /// `&`
        pub const AMPERSAND: u8 = 38;
        /// `>`
        pub const PIPE: u8 = 62;
    }
    pub use chars::*;

    pub const EXTENSION_PREFIX: &[u8] = &[BANG, PIPE];
    pub const EXTENSION_AND: &[u8] = &[AMPERSAND, PIPE];

    pub fn parse_args(bytes: &[u8]) -> (Vec<Vec<String>>, usize) {
        let mut segments = Vec::with_capacity(bytes.windows(2).fold(1, |acc, value| {
            if value == EXTENSION_AND {
                acc + 1
            } else {
                acc
            }
        }));
        let mut args =
            Vec::with_capacity(bytes.iter().fold(
                1,
                |acc, value| {
                    if *value == SPACE {
                        acc + 1
                    } else {
                        acc
                    }
                },
            ));
        let mut last_break = 0;
        let mut current_index = 0;
        let mut last_was_ampersand = false;
        for byte in bytes {
            if *byte == LF {
                if current_index - last_break > 1 {
                    let string = String::from_utf8(
                        bytes[last_break..if bytes.get(current_index - 1) == Some(&CR) {
                            current_index - 1
                        } else {
                            current_index
                        }]
                            .to_vec(),
                    );
                    if let Ok(string) = string {
                        args.push(string);
                    }
                }
                break;
            }
            if *byte == SPACE && current_index - last_break > 1 {
                let string = String::from_utf8(bytes[last_break..current_index].to_vec());
                if let Ok(string) = string {
                    args.push(string);
                }
            }
            if last_was_ampersand {
                if *byte == PIPE {
                    // New segment!
                    segments.push(args.split_off(0));
                    // Can be directly after, since a space won't get added, len needs to be more than 0!
                    last_break = current_index + 1;
                }
                last_was_ampersand = false;
            }
            if *byte == AMPERSAND {
                last_was_ampersand = true;
            }
            current_index += 1;
            if *byte == SPACE {
                last_break = current_index;
            }
        }
        if !args.is_empty() {
            segments.push(args);
        }
        // Plus one, since loop breaks before newline
        (segments, current_index + 1)
    }
    pub fn extension_args(bytes: &[u8]) -> (Vec<Vec<String>>, usize) {
        if bytes.starts_with(EXTENSION_PREFIX) {
            let (vec, content_start) = parse_args(&bytes[EXTENSION_PREFIX.len()..]);
            // Add EXTENSION_PREFIX.len(), since the fn started counting as though byte 0 was EXTENSION_PREFIX.len() actual byte.
            (vec, content_start + EXTENSION_PREFIX.len())
        } else {
            (Vec::new(), 0)
        }
    }
}

pub fn exit_with_message(message: &str) -> ! {
    eprintln!("{}", message);
    wait_for("Press enter to close...");
    std::process::exit(1)
}

pub(crate) mod filesystem {
    use super::*;
    use std::{
        fs::{File, Metadata, OpenOptions},
        io::ErrorKind,
    };
    pub fn open_file_with_metadata<P: AsRef<Path>>(path: P) -> (File, Metadata) {
        match File::open(path).and_then(|file| file.metadata().map(|metadata| (file, metadata))) {
            Ok(file) => file,
            Err(err) => match err.kind() {
                ErrorKind::NotFound => {
                    exit_with_message("File not found, please check the entered path.")
                }
                ErrorKind::PermissionDenied => {
                    exit_with_message("You do not have permission to read the file specified.")
                }
                _ => exit_with_message("Encountered an unknown error reading the file specified."),
            },
        }
    }
    pub fn create_file<P: AsRef<Path>>(path: P) -> File {
        fn open<P: AsRef<Path>>(options: &OpenOptions, path: P) -> File {
            match options.open(&path) {
                Ok(file) => file,
                Err(err) => match err.kind() {
                    ErrorKind::AlreadyExists => {
                        match read_continue("The existing .html file will be overriden.", true) {
                            false => exit_with_message("Aborted conversion."),
                            // Continue as normal
                            true => {}
                        };
                        open(
                            OpenOptions::new().write(true).create(true).truncate(true),
                            path,
                        )
                    }
                    ErrorKind::NotFound => {
                        exit_with_message("File not found, please check the entered path.")
                    }
                    ErrorKind::PermissionDenied => {
                        exit_with_message("You do not have permission to read the file specified.")
                    }
                    _ => exit_with_message(
                        "Encountered an unknown error reading the file specified.",
                    ),
                },
            }
        }
        open(
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .truncate(true),
            path,
        )
    }
}

#[must_use = "you have promted the user for input, so use it"]
/// The message is in the beginning of the println! so it should be capitalized and contain a punctuation marking the end of a sentence (e.g. `.?!`).
/// The message should not contain the word continue, since it is used extensively in this fn.
pub fn read_continue(message: &str, default: bool) -> bool {
    println!(
        "{} Do you want to continue (y or n)? Press enter to continue with '{}'.",
        message,
        if default == true { "yes" } else { "no" }
    );
    loop {
        let mut buffer = [0; 64];
        let read = match io::stdin().lock().read(&mut buffer) {
            Ok(read) => read,
            Err(_) => {
                eprintln!("Failed to read stdin for confirmation.");
                return false;
            }
        };
        let read = match buffer.get(read - 2) {
            Some(byte) if *byte == parse::CR => read - 2,
            Some(_) if buffer.get(read - 1) == Some(&parse::LF) => read - 1,
            _ => read,
        };
        match &buffer[..read] {
            b"y" => break true,
            b"Y" => break true,
            b"yes" => break true,
            b"Yes" => break true,
            b"YES" => break true,
            b"n" => break false,
            b"N" => break false,
            b"no" => break false,
            b"No" => break false,
            b"NO" => break false,
            b"" => break default,
            _ => println!(
                "Could not detect your intent. Please try again. {}",
                message
            ),
        }
    }
}

#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Copy, Clone)]
pub enum FileEnding {
    LF,
    CRLF,
}
impl FileEnding {
    pub fn find(bytes: &[u8]) -> Option<Self> {
        for byte_pair in bytes.windows(2) {
            if byte_pair.get(1) == Some(&parse::LF) {
                match byte_pair.get(0) {
                    Some(&parse::CR) => return Some(Self::CRLF),
                    Some(_) => return Some(Self::LF),
                    None => {}
                }
            }
        }
        None
    }
    pub fn as_bytes(&self) -> &'static [u8] {
        match self {
            Self::LF => b"\n",
            Self::CRLF => b"\r\n",
        }
    }
}

/// Will process the document at the given path.
///
/// If an Kvarn extension resides in the beginning of the header, make sure it has a newline in the end if only extension declaration; else parsing will fail.
///
/// # Errors
/// Will only throw a error if writing to the output file failed. Else, it terminates the application.
///
/// # Panics
/// If any unexpected event occurs, it will exit the application gracefully. This is not ment as a helper function.
pub fn process_document<P: AsRef<Path>>(
    path: P,
    header: &[u8],
    footer: &[u8],
    ignored_extensions: &[&str],
) -> io::Result<()> {
    let path = path.as_ref();
    if path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|s| s == "md")
        == Some(false)
    {
        println!("Specified file is not of type '.md' This conversion be a mistake and make a unexpected result.");
    }
    let (mut file, metadata) = filesystem::open_file_with_metadata(&path);
    let new_path = {
        let mut path = path.to_owned();
        path.set_extension("html");
        path
    };
    let mut write_file = io::BufWriter::new(filesystem::create_file(&new_path));

    let mut buffer = Vec::with_capacity(metadata.len() as usize); // ToDo: Remove `as usize`
    if file.read_to_end(&mut buffer).is_err() {
        exit_with_message("Encountered an error reading the contents of the file specified.")
    }
    let (mut extensions, header_content_starts) = parse::extension_args(header);

    let (file_extensions, file_content_start) = parse::extension_args(&buffer[..]);
    'extension_loop: for extension in file_extensions.into_iter() {
        // If extension name is present
        let extension_name = match extension.get(0) {
            Some(e) => e.as_str(),
            None => continue,
        };
        // Check for ignored extensions, and skip pushing it to main extensions if matched
        for ignored in ignored_extensions {
            if *extension_name == **ignored {
                continue 'extension_loop;
            }
        }
        // Push to main extension list
        extensions.push(extension);
    }
    // Write all extensions
    for (position, extension) in extensions.iter().enumerate() {
        match position {
            // Write !> in first iteration, &> in the rest!
            0 => {
                write_file.write(b"!>")?;
                for arg in extension {
                    write_file.write(b" ")?;
                    write_file.write_all(arg.as_bytes())?;
                }
            }
            _ => {
                write_file.write(b" &>")?;
                for arg in extension {
                    write_file.write(b" ")?;
                    write_file.write_all(arg.as_bytes())?;
                }
            }
        }
    }
    // Write newline after extensions, ~depending on what file ending is used in the file~.
    // Update, Pulldown-CMark only writes LF, even if input file is CRLF. I will also write LF then ¯\_(ツ)_/¯
    write_file.write(
        // FileEnding::find(&buffer[..])
        //     .unwrap_or(FileEnding::LF)
        //     .as_bytes(),
        FileEnding::LF.as_bytes(),
    )?;

    // Write rest of header
    write_file.write_all(&header[header_content_starts..])?;

    // Parse CMark
    let input = unsafe { std::str::from_utf8_unchecked(&buffer[file_content_start..]) };
    let parser = Parser::new_ext(input, Options::all());

    // Write HTML from specified file to output file (buffered for performance)
    html::write_html(&mut write_file, parser)?;

    // Writes footer
    write_file.write_all(footer)?;
    // Flushes the buffered writer
    write_file.flush()?;

    println!("Done converting CommonMark to HTML.");

    Ok(())
}

/// Blocks while waiting for the user to press enter, displaying the message specified.
#[inline]
pub fn wait_for(message: &str) {
    println!("{}", message);
    let _ = io::stdin().read(&mut [0; 0]);
}
