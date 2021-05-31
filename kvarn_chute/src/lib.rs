use pulldown_cmark::{html, CowStr, Event, Options, Parser, Tag};
use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::fmt;
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
    pub fn open_file_with_metadata<P: AsRef<Path>>(path: P) -> io::Result<(File, Metadata)> {
        match File::open(path).and_then(|file| file.metadata().map(|metadata| (file, metadata))) {
            Ok(file) => Ok(file),
            Err(err) => match err.kind() {
                ErrorKind::NotFound => {
                    exit_with_message("File not found, please check the entered path.")
                }
                ErrorKind::PermissionDenied => Err(err),
                _ => exit_with_message("Encountered an unknown error reading the file specified."),
            },
        }
    }
    pub fn create_file<P: AsRef<Path>>(path: P, quiet: bool) -> File {
        fn open<P: AsRef<Path>>(options: &OpenOptions, path: P, quiet: bool) -> File {
            match options.open(&path) {
                Ok(file) => file,
                Err(err) => match err.kind() {
                    ErrorKind::AlreadyExists => {
                        if !quiet {
                            match read_continue("The existing .html file will be overriden.", true)
                            {
                                false => exit_with_message("Aborted conversion."),
                                // Continue as normal
                                true => {}
                            };
                        }
                        open(
                            OpenOptions::new().write(true).create(true).truncate(true),
                            path,
                            quiet,
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
            quiet,
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
        if default { "yes" } else { "no" }
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
    Lf,
    CrLf,
}
impl FileEnding {
    pub fn find(bytes: &[u8]) -> Option<Self> {
        for byte_pair in bytes.windows(2) {
            if byte_pair.get(1) == Some(&parse::LF) {
                match byte_pair.get(0) {
                    Some(&parse::CR) => return Some(Self::CrLf),
                    Some(_) => return Some(Self::Lf),
                    None => {}
                }
            }
        }
        None
    }
    pub fn as_bytes(&self) -> &'static [u8] {
        match self {
            Self::Lf => b"\n",
            Self::CrLf => b"\r\n",
        }
    }
}

/// Will process the document at the given path.
///
/// If a Kvarn extension resides in the beginning of the header, make sure it has a newline in the end if only extension declaration; else parsing will fail.
///
/// # Errors
/// Will throw a error if writing to the output file failed or if the file specified cannot be accessed (privileges, if it's a folder). Else, it terminates the application.
///
/// # Panics
/// If any unexpected event occurs, it will exit the application gracefully. This is not ment as a helper function.
pub fn process_document<P: AsRef<Path>>(
    path: P,
    header_pre_meta: &[u8],
    header_post_meta: &[u8],
    footer: &[u8],
    ignored_extensions: &[&str],
    quiet: bool,
) -> io::Result<()> {
    let path = path.as_ref();
    if path.extension().and_then(OsStr::to_str).map(|s| s == "md") == Some(false) {
        println!("Specified file is not of type '.md' This conversion be a mistake and make a unexpected result.");
    }
    let (mut file, metadata) = filesystem::open_file_with_metadata(&path)?;
    let new_path = {
        let mut path = path.to_owned();
        path.set_extension("html");
        path
    };
    let mut write_file = io::BufWriter::new(filesystem::create_file(&new_path, quiet));

    let mut buffer = Vec::with_capacity(metadata.len() as usize); // ToDo: Remove `as usize`
    if file.read_to_end(&mut buffer).is_err() {
        exit_with_message("Encountered an error reading the contents of the file specified.")
    }
    let (mut extensions, header_content_starts) = parse::extension_args(header_pre_meta);

    let (file_extensions, mut file_content_start) = parse::extension_args(&buffer[..]);
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
    if let Ok(string) = std::str::from_utf8(&buffer[file_content_start..]) {
        let white_space_chars = string.char_indices().take_while(|(_, char)| char.is_whitespace()).last().map_or(0, |(pos, char)| pos + char.len_utf8());

        file_content_start += white_space_chars;
    }
    // Write all extensions
    for (position, extension) in extensions.iter().enumerate() {
        match position {
            // Write !> in first iteration, &> in the rest!
            0 => {
                write_file.write_all(b"!>")?;
                for arg in extension {
                    write_file.write_all(b" ")?;
                    write_file.write_all(arg.as_bytes())?;
                }
            }
            _ => {
                write_file.write_all(b" &>")?;
                for arg in extension {
                    write_file.write_all(b" ")?;
                    write_file.write_all(arg.as_bytes())?;
                }
            }
        }
    }
    // Write newline after extensions, ~depending on what file ending is used in the file~.
    // Update, Pulldown-CMark only writes LF, even if input file is CRLF. I will also write LF then ¯\_(ツ)_/¯
    write_file.write_all(FileEnding::Lf.as_bytes())?;

    // Write rest of header before meta
    write_file.write_all(&header_pre_meta[header_content_starts..])?;

    // If we have a head tag
    let file_content_start = if buffer[file_content_start..].starts_with(b"<head>") {
        let buffer = &buffer[file_content_start..];
        let end = buffer
            .windows(7)
            .position(|slice| slice == b"</head>")
            .unwrap_or(buffer.len());

        write_file.write_all(&buffer[6..end])?;

        file_content_start + end + 7
    } else {
        file_content_start
    };

    // Write header after meta
    write_file.write_all(header_post_meta)?;

    let input = std::str::from_utf8(&buffer[file_content_start..])
        .expect("we tried to split the beginning of MarkDown on a character boundary, or the input file isn't valid UTF-8");

    let mut tags: Tags = HashMap::new();
    #[cfg(feature = "date")]
    tags.insert(
        "date".to_owned(),
        Box::new(|_inner, mut ext| {
            let date = chrono::Local::now();
            use fmt::Write;
            write!(ext, "{}", date.format("%a, %F, %0H:%0M %:z"))
                .expect("failed to push to string");
        }),
    );

    let input = replace_tags(input, tags);

    // Parse CMark
    let parser = Parser::new_ext(&input, Options::all());

    let mut header_ids = HashSet::new();
    let with_tagged_headers = map_peek(parser, |event, next| match (&event, next) {
        (Event::Start(Tag::Heading(level)), Some(Event::Text(header_text))) => {
            let id = resolve_id(header_text, &mut header_ids);
            let html = format!("<h{} id=\"{}\">", level, id);
            Event::Html(CowStr::Boxed(html.into_boxed_str()))
        }
        _ => event,
    });

    // Write HTML from specified file to output file (buffered for performance)
    html::write_html(&mut write_file, with_tagged_headers)?;

    // Writes footer
    write_file.write_all(footer)?;
    // Flushes the buffered writer
    write_file.flush()?;

    if !quiet {
        println!("Done converting CommonMark to HTML.");
    }

    Ok(())
}

fn resolve_id<'a>(next: &str, map: &'a mut HashSet<String>) -> &'a str {
    let mut next = make_anchor(next);

    let mut added_suffix = false;
    while map.contains(&next) {
        if !added_suffix {
            next.push_str("-1");
            added_suffix = true;
            continue;
        }
        let pos = next.rfind('-').unwrap_or_else(|| next.len());
        // We know this lies on a valid boundary from the above code.
        let number: u32 = next.get(pos + 1..).unwrap().parse().unwrap_or(1) + 1;
        let to_remove = next.len() - pos - 1;
        for _ in 0..to_remove {
            next.pop();
        }
        use fmt::Write;
        write!(next, "{}", number).expect("failed to write to string");
    }
    insert_hashset(map, next)
}
fn insert_hashset(map: &mut HashSet<String>, value: String) -> &str {
    let pointer: *const str = value.as_str();
    map.insert(value);
    // Safe because the value is now owned by the map.
    // Unwrap is ok; we just inserted the value.
    map.get(unsafe { &*pointer }).unwrap()
}

/// Will watch the given directory.
///
/// If a Kvarn extension resides in the beginning of the header, make sure it has a newline in the end if only extension declaration; else parsing will fail.
///
/// # Errors
/// Will throw a error if writing to the output file failed or if the file specified cannot be accessed (privileges, if it's a folder). Else, it terminates the application.
///
/// # Panics
/// If any unexpected event occurs, it will exit the application gracefully. This is not ment as a helper function.
pub fn watch<P: AsRef<Path>>(
    path: P,
    header_pre_meta: &[u8],
    header_post_meta: &[u8],
    footer: &[u8],
    ignored_extensions: &[&str],
) -> io::Result<()> {
    use notify::{watcher, DebouncedEvent::*, RecursiveMode, Watcher};
    use std::sync::mpsc::channel;
    use std::time::Duration;
    // Create a channel to receive the events.
    let (tx, rx) = channel();

    // Create a watcher object, delivering debounced events.
    // The notification back-end is selected based on the platform.
    let mut watcher = watcher(tx, Duration::from_millis(100)).unwrap();

    // Add a path to be watched. All files and directories at that path and
    // below will be monitored for changes.
    watcher
        .watch(path.as_ref(), RecursiveMode::Recursive)
        .unwrap();

    loop {
        match rx.recv() {
            Ok(event) => match event {
                Write(path) | Create(path) | Rename(_, path) => {
                    if path.extension().and_then(OsStr::to_str) == Some("md") {
                        process_document(
                            &path,
                            header_pre_meta,
                            header_post_meta,
                            footer,
                            ignored_extensions,
                            true,
                        )?;
                        let local_path = if let Ok(wd) = std::env::current_dir() {
                            path.strip_prefix(wd).unwrap_or(&path)
                        } else {
                            &path
                        };
                        if let Some(path) = local_path.to_str() {
                            println!("Converted {} to html!", path);
                        }
                    }
                }
                _ => {}
            },
            Err(_) => exit_with_message("Got an error watching the specified directory."),
        }
    }
}

/// Blocks while waiting for the user to press enter, displaying the message specified.
#[inline]
pub fn wait_for(message: &str) {
    println!("{}", message);
    let _ = io::stdin().read(&mut [0; 0]);
}
struct MapPeek<T, I: Iterator<Item = T>, F> {
    iter: std::iter::Peekable<I>,
    func: F,
}
impl<T, I: Iterator<Item = T>, F: FnMut(T, Option<&T>) -> T> Iterator for MapPeek<T, I, F> {
    type Item = T;
    fn next(&mut self) -> Option<Self::Item> {
        let next = self.iter.next();
        if let Some(next) = next {
            let peek = self.iter.peek();
            Some((self.func)(next, peek))
        } else {
            None
        }
    }
}
fn map_peek<T, I: Iterator<Item = T>, F: FnMut(T, Option<&T>) -> T>(
    iter: I,
    f: F,
) -> MapPeek<T, I, F> {
    MapPeek {
        iter: iter.peekable(),
        func: f,
    }
}

pub struct Extendible<'a> {
    inner: &'a mut String,
}
impl<'a> Extendible<'a> {
    pub fn extend(&mut self, string: &str) {
        self.inner.push_str(string);
    }
}
impl<'a> fmt::Write for Extendible<'a> {
    fn write_fmt(&mut self, args: fmt::Arguments<'_>) -> fmt::Result {
        self.inner.write_fmt(args)
    }
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.inner.push_str(s);
        Ok(())
    }
}

pub fn make_anchor(title: &str) -> String {
    let lowercase = title.to_lowercase();
    let mut a = String::with_capacity(lowercase.len());
    for char in lowercase.chars() {
        match char {
            ' ' => a.push('-'),
            _ if char.is_ascii_alphanumeric() => a.push(char),
            _ => {}
        }
    }
    a
}

pub type Tags = HashMap<String, Box<dyn Fn(&str, Extendible)>>;

pub fn replace_tags(text: &str, tags: Tags) -> String {
    let mut string = String::with_capacity(text.len() + 64);

    let mut in_tag = false;
    let mut escaped_tag = false;

    for (index, char) in text.char_indices() {
        let text = unsafe { text.get_unchecked(index..) };
        if text.starts_with("${") {
            if !escaped_tag {
                for (name, func) in &tags {
                    let tag_len = name.len() + 2 + 1;
                    if !in_tag
                        && text
                            .get(..tag_len)
                            .map_or(false, |text| text.ends_with('}'))
                    {
                        // For unwrap, see above.
                        let inner = text.get(2..tag_len - 1).unwrap();
                        // ~~We are guaranteed to have at least one; if there are no spaces, we still get one~~
                        // If the string is 0 in length, we return the first word as a empty string.
                        let first_word = inner.split(' ').next().unwrap_or("");
                        if first_word == name {
                            let ext = Extendible { inner: &mut string };
                            func(inner, ext);
                            in_tag = true;
                            break;
                        }
                    }
                }
            }
            if escaped_tag {
                string.pop();
            }
        }
        if in_tag {
            if char == '}' {
                in_tag = false;
            }
        } else {
            string.push(char);
        }
        if char == '\\' {
            escaped_tag = !escaped_tag;
        } else {
            escaped_tag = false;
        }
    }
    string
}
