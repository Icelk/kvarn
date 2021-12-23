use pulldown_cmark::{html, CowStr, Event, Options, Parser, Tag};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fmt::{self, Display, Formatter};
use std::io::{self, prelude::*};
use std::path::Path;
use unicode_categories::UnicodeCategories;

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
    let mut write_file = filesystem::create_file(&new_path, quiet);

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
        let white_space_chars = string
            .char_indices()
            .take_while(|(_, char)| char.is_whitespace())
            .last()
            .map_or(0, |(pos, char)| pos + char.len_utf8());

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

    let mut headers = Vec::new();
    get_headers(&mut headers, input);

    let mut tags: Tags = HashMap::new();
    tags.insert(
        "toc".to_owned(),
        Box::new(|_inner, mut ext| {
            struct MarginDisplay<'a> {
                counter: &'a IndentCounter,
                multiplier: usize,
            }
            impl<'a> Display for MarginDisplay<'a> {
                fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                    let margin = self.counter.left_margin(self.multiplier);

                    if margin == 0 {
                        Ok(())
                    } else {
                        write!(f, "<span style=\"margin-left: {}em\"></span>", margin)
                    }
                }
            }

            let mut indent_counter = IndentCounter::new();
            use fmt::Write;
            write!(ext, "|Contents|\n|---|\n").unwrap();
            for Header {
                name,
                anchor,
                indent,
            } in &headers
            {
                indent_counter.add(*indent);
                let margin = MarginDisplay {
                    counter: &indent_counter,
                    multiplier: 2,
                };

                writeln!(
                    ext,
                    "|{} [{} {}](#{})|",
                    margin, indent_counter, name, anchor
                )
                .unwrap();
            }
        }),
    );
    #[cfg(feature = "date")]
    tags.insert(
        "date".to_owned(),
        Box::new(|_inner, mut ext| {
            use fmt::Write;
            let date = chrono::Local::now();
            write!(ext, "{}", date.format("%a, %F, %0H:%0M %:z"))
                .expect("failed to push to string");
        }),
    );

    let input = replace_tags(input, tags);

    // Parse CMark
    let parser = Parser::new_ext(&input, Options::all());

    let mut parser_header_index = 0;
    let parser = parser.map(|event| match event {
        Event::Start(Tag::Heading(level, _, classes)) => {
            let Header { anchor, .. } = &headers[parser_header_index];
            parser_header_index += 1;

            let class = if classes.is_empty() {
                String::new()
            } else {
                const START: &str = " class=\"";
                const END: &str = r#"""#;
                let mut s = String::with_capacity(
                    classes.iter().fold(START.len() + END.len(), |acc, class| {
                        acc + class.len() + " ".len()
                    }),
                );

                s.push_str(START);
                for class in &classes {
                    s.push_str(class);
                    s.push(' ');
                }
                s.push_str(END);

                s
            };

            let html = format!("<{} id=\"{}\"{}>", level, anchor, class);
            Event::Html(CowStr::Boxed(html.into_boxed_str()))
        }
        _ => event,
    });

    let mut output = Vec::with_capacity(input.len() * 2);

    // Write HTML from specified file to output file (buffered for performance)
    html::write_html(&mut output, parser)?;

    // Write output
    write_file.write_all(&output)?;

    // Writes footer
    write_file.write_all(footer)?;
    write_file.flush()?;

    if !quiet {
        println!("Done converting CommonMark to HTML.");
    }

    Ok(())
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

/// It's safe to unwrap on the [`fmt::Write`] trait; we're writing to a [`String`].
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

pub fn make_anchor(headers: &[Header], title: &str) -> String {
    fn is_parenthesis(c: char) -> bool {
        matches!(c, '(' | ')' | '[' | ']' | '{' | '}')
    }
    let lowercase = title.to_lowercase();
    let mut a = String::with_capacity(lowercase.len());
    let mut in_parenthesis = false;
    for char in lowercase.chars() {
        match char {
            ' ' if !in_parenthesis => a.push('-'),
            _ if is_parenthesis(char) => in_parenthesis = !in_parenthesis,
            _ if !in_parenthesis && char.is_ascii_alphanumeric() => a.push(char),
            _ => {}
        }
    }
    {
        let mut last_number = 0_u32;
        let mut last_number_length = 0_u32;
        while headers.iter().any(|header| header.anchor == a) {
            if last_number_length == 0 {
                a.push_str("-1");
            } else {
                for _ in 0..last_number_length {
                    a.pop();
                }
                let number = (last_number + 1).to_string();

                a.push_str(&number);

                last_number_length = number.len() as u32;
                last_number += 1;
            }
        }
    }
    a
}

pub type Tags<'a> = HashMap<String, Box<dyn Fn(&'a str, Extendible) + 'a>>;

pub fn replace_tags<'a>(text: &'a str, tags: Tags<'a>) -> String {
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

#[derive(Debug)]
pub struct Header<'a> {
    name: &'a str,
    anchor: String,
    indent: u8,
}
pub fn get_headers<'a>(headers: &mut Vec<Header<'a>>, input: &'a str) {
    fn is_parenthesis(c: char) -> bool {
        matches!(c, '(' | ')' | '[' | ']' | '{' | '}')
    }
    let mut in_code = false;
    for (line, next_line) in input
        .lines()
        .zip(input.lines().skip(1).map(Some).chain(std::iter::once(None)))
    {
        let trimmed = line.trim();
        let header_trimmed = trimmed.trim_start_matches('#');
        let indent = (trimmed.len() - header_trimmed.len())
            .wrapping_sub(1)
            .min(next_line.map_or(usize::MAX, |next_line| {
                if !trimmed.is_empty()
                    && (next_line.trim().starts_with("---") || next_line.trim().starts_with("==="))
                {
                    0
                } else {
                    usize::MAX
                }
            }))
            .wrapping_add(1);

        if trimmed.starts_with("```") {
            in_code = !in_code;
        }

        if !in_code && indent > 0 {
            let heavily_trimmed = header_trimmed.trim_start_matches(|c: char| !c.is_alphabetic());
            let split_using_parentheses = header_trimmed.contains("](");
            let heavily_trimmed = heavily_trimmed
                .split(|c: char| {
                    !(c.is_alphanumeric()
                        || c.is_ascii_punctuation()
                        || c.is_whitespace()
                        || c.is_punctuation())
                        || (split_using_parentheses && is_parenthesis(c))
                })
                .next()
                .unwrap_or(heavily_trimmed);

            let anchor = make_anchor(headers, heavily_trimmed);
            let indent = indent.min(255) as u8;

            headers.push(Header {
                name: heavily_trimmed,
                anchor,
                indent,
            });
        }
    }
}
#[derive(Debug)]
pub struct IndentCounter {
    indent_index: [u8; 6],
    last_indent: u8,
}
impl IndentCounter {
    pub fn new() -> Self {
        Self {
            indent_index: [0; 6],
            last_indent: 0,
        }
    }
    pub fn add(&mut self, indent: u8) {
        let indent = indent - 1;
        if self.last_indent > indent {
            self.indent_index[self.last_indent as usize] = 0;
        }
        self.indent_index[indent as usize] += 1;
        self.last_indent = indent;
    }
    pub fn indent(&self) -> IndentIndenter {
        IndentIndenter { data: self }
    }
    pub fn left_margin(&self, multiplier: usize) -> usize {
        self.last_indent as usize * multiplier
    }
}
impl Default for IndentCounter {
    fn default() -> Self {
        Self::new()
    }
}
impl Display for IndentCounter {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        for i in 0..self.last_indent {
            write!(f, "{}.", self.indent_index[i as usize])?;
        }
        write!(f, "{}", self.indent_index[self.last_indent as usize])
    }
}
#[derive(Debug)]
pub struct IndentIndenter<'a> {
    data: &'a IndentCounter,
}
impl<'a> Display for IndentIndenter<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        for _ in 0..self.data.last_indent {
            write!(f, "    ")?;
        }
        Ok(())
    }
}
