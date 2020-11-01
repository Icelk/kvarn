// For when no features are present
#[allow(unused_imports)]
use crate::chars::*;
#[allow(unused_imports)]
use crate::{read_file, Storage};

#[cfg(feature = "php")]
pub use php::handle_php as php;
#[cfg(feature = "templates")]
pub use templates::handle_template as template;

/// All known extensions
#[derive(Debug)]
pub enum KnownExtension {
    #[cfg(feature = "php")]
    PHP,
    #[cfg(feature = "templates")]
    Template,
    SetCache,
}
/// What type is this file, raw, unknown extension, or known extension?
#[derive(Debug)]
pub enum FileType<'a> {
    Raw,
    UnknownExtension(usize, Vec<&'a [u8]>),
    DefinedExtension(KnownExtension, usize, Vec<&'a [u8]>),
}

#[cfg(feature = "php")]
pub mod php {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
    use std::path::PathBuf;
    use std::{
        fs::File,
        io::{self, prelude::*},
    };

    #[allow(unused_variables)]
    pub fn handle_php<W: Write>(
        socket: &mut W,
        request: &[u8],
        path: &PathBuf,
    ) -> Result<(), io::Error> {
        unimplemented!();

        // Take the thread name and make a file of that instead. Try the line for line mode instead.
        let mut temp = File::create("temp.php")?;
        let mut file = File::open(path)?;
        let mut buffer = [0; 4096];
        let mut first = true;
        loop {
            let read = match file.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => read,
                Err(ref err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) => return Err(err),
            };
            if read == 0 {
                break;
            }
            if first {
                let read_till = {
                    let mut out = 0;
                    for byte in buffer.iter() {
                        out += 1;
                        if *byte == 10 {
                            break;
                        }
                    }
                    out
                };
                println!("Discard first {}", read_till);
                temp.write_all(&mut &buffer[read_till..read])?;
                first = false;
            } else {
                temp.write_all(&mut buffer[..read])?;
            }
        }

        let mut php = match TcpStream::connect(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::LOCALHOST,
            6633,
        ))) {
            Err(err) => {
                panic!("Failed to get PHP: {:?}", err);
            }
            Ok(socket) => socket,
        };

        todo!("Change path to /temp.php! Or implement interpreter!");
        php.write_all(request)?;
        loop {
            let mut buffer = [0; 4096];
            let read = match php.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => read,
                Err(ref err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) => return Err(err),
            };
            socket.write_all(&mut buffer[0..read])?;
        }

        Ok(())
    }
}

#[cfg(feature = "templates")]
pub mod templates {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::{collections::HashMap, str};

    pub fn handle_template(arguments: &[&[u8]], file: &[u8], storage: &mut Storage) -> Vec<u8> {
        // Get templates, from cache or file
        let templates = read_templates(arguments.iter().skip(1).copied(), storage);

        #[derive(Eq, PartialEq)]
        enum Stage {
            Text,
            Placeholder,
        };

        let mut response = Vec::new();

        let mut stage = Stage::Text;
        let mut placeholder_start = 0;
        let mut escaped = 0;
        for (position, byte) in file.iter().enumerate() {
            let is_escape = *byte == ESCAPE;

            match stage {
                // If in text stage, check for left bracket. Then set the variables for starting identifying the placeholder for template
                // Push the current byte to response, if not start of placeholder
                Stage::Text if (escaped == 0 && !is_escape) || escaped == 1 => {
                    if *byte == L_SQ_BRACKET && escaped != 1 {
                        placeholder_start = position;
                        stage = Stage::Placeholder;
                    } else {
                        response.push(*byte);
                    }
                }
                Stage::Placeholder if escaped != 1 => {
                    // If placeholder closed
                    if *byte == R_SQ_BRACKET {
                        // Check if name is longer than empty
                        if position.checked_sub(placeholder_start + 2).is_some() {
                            // Good; we have UTF-8
                            if let Ok(key) = str::from_utf8(&file[placeholder_start + 1..position])
                            {
                                // If it is a valid template?
                                // Frick, we have to own the value for it to be borrow for Arc<String>, no &str here :(
                                if let Some(template) = templates.get(&key.to_owned()) {
                                    // Push template byte-slice to the response
                                    for byte in &**template {
                                        response.push(*byte);
                                    }
                                }
                            }
                        }
                        // Set stage to accept new text
                        stage = Stage::Text;
                    }
                }
                // Else, it's a escaping character!
                _ => {}
            }

            // Do we escape?
            if is_escape {
                escaped += 1;
                if escaped == 2 {
                    escaped = 0;
                }
            } else {
                escaped = 0;
            }
        }
        response
    }
    fn read_templates<'a, I: DoubleEndedIterator<Item = &'a [u8]>>(
        files: I,
        storage: &mut Storage,
    ) -> HashMap<Arc<String>, Arc<Vec<u8>>> {
        let mut templates = HashMap::with_capacity(32);

        for template in files.rev() {
            if let Ok(template) = str::from_utf8(template) {
                if let Some(map) = read_templates_from_file(template, storage) {
                    for (key, value) in map.iter() {
                        templates.insert(Arc::clone(key), Arc::clone(value));
                    }
                }
            }
        }

        templates
    }
    fn read_templates_from_file(
        template_set: &str,
        storage: &mut Storage,
    ) -> Option<Arc<HashMap<Arc<String>, Arc<Vec<u8>>>>> {
        if let Some(lock) = storage.try_template() {
            if let Some(template) = lock.get(template_set) {
                return Some(template);
            }
        }
        let mut template_dir = PathBuf::from("templates");
        template_dir.push(template_set);

        match read_file(&template_dir, storage.get_fs()) {
            Some(file) => {
                let templates = Arc::new(extract_templates(&file[..]));
                match storage.try_template() {
                    Some(mut cache) => match cache.cache(template_set.to_owned(), templates) {
                        Err(failed) => Some(failed),
                        Ok(()) => Some(cache.get(template_set).unwrap()),
                    },
                    None => Some(templates),
                }
            }
            None => None,
        }
    }
    fn extract_templates(file: &[u8]) -> HashMap<Arc<String>, Arc<Vec<u8>>> {
        let mut templates = HashMap::with_capacity(16);

        let mut last_was_lf = true;
        let mut escape = false;
        let mut name_start = 0;
        let mut name_end = 0usize;
        let mut newline_size = 1;
        for (position, byte) in file.iter().enumerate() {
            // Ignore all CR characters
            if *byte == CR {
                newline_size = 2;
                continue;
            }
            // If previous char was \, escape!
            // New template, process previous!
            if !escape && last_was_lf && *byte == L_SQ_BRACKET {
                // If name is longer than empty
                if name_end.checked_sub(name_start + 2).is_some() {
                    // Check if we have a valid UTF-8 string
                    if let Ok(name) = str::from_utf8(&file[name_start + 1..name_end - 1]) {
                        // Check if value comes after newline, space, or right after. Then remove the CRLF/space from template value
                        let add_after_name = if file.get(name_end + newline_size - 1) == Some(&LF) {
                            newline_size
                        } else {
                            if file.get(name_end) == Some(&SPACE) {
                                1
                            } else {
                                0
                            }
                        };
                        // Then insert template; name we got from previous step, then bytes from where the previous template definition ended, then our current position, just before the start of the next template
                        // Returns a byte-slice of the file
                        templates.insert(
                            Arc::new(name.to_owned()),
                            Arc::new(
                                file[name_end + add_after_name..position - newline_size].to_vec(),
                            ),
                        );
                    }
                }
                // Set start of template name to now
                name_start = position;
            }
            if *byte == R_SQ_BRACKET {
                name_end = position + 1;
            }

            last_was_lf = *byte == LF;
            escape = *byte == ESCAPE;
        }
        // Because we add the definitions in the start of the new one, check for last in the end of file
        if name_end.checked_sub(name_start + 2).is_some() {
            if let Ok(name) = str::from_utf8(&file[name_start + 1..name_end - 1]) {
                // Check if value comes after newline, space, or right after. Then remove the CRLF/space from template value
                let add_after_name = if file.get(name_end + newline_size - 1) == Some(&LF) {
                    newline_size
                } else {
                    if file.get(name_end) == Some(&SPACE) {
                        1
                    } else {
                        0
                    }
                };
                templates.insert(
                    Arc::new(name.to_owned()),
                    Arc::new(file[name_end + add_after_name..file.len() - newline_size].to_vec()),
                );
            }
        }
        templates
    }
}

const EXTENSION_PREFIX: &[u8] = &[BANG, PIPE];

pub fn identify<'a, 'b>(bytes: &'a [u8], file_extension: Option<&'b str>) -> FileType<'a> {
    use FileType::*;
    use KnownExtension::*;

    // If file starts with "!>", meaning it's an extension-dependent file!
    if bytes.starts_with(EXTENSION_PREFIX) {
        // Get extention arguments
        let (args, content_start) = parse_args(&bytes[EXTENSION_PREFIX.len()..]);
        // Add two, because of the BANG and PIPE start!
        let content_start = content_start + 2;

        if let Some(test) = args.get(0) {
            match test {
                #[cfg(feature = "php")]
                &b"php" => DefinedExtension(PHP, content_start, args),
                #[cfg(feature = "templates")]
                &b"tmpl" if args.len() > 1 => DefinedExtension(Template, content_start, args),
                &b"cache" => DefinedExtension(SetCache, content_start, args),
                // If extension not found in file, check file ending!
                _ => match file_extension {
                    #[cfg(feature = "php")]
                    Some(".php") => DefinedExtension(PHP, content_start, args),
                    // If nothing found, return a new body, with the extension ripped out!
                    _ => UnknownExtension(content_start, args),
                },
            }
        } else {
            Raw
        }
    } else {
        Raw
    }
}
fn parse_args(bytes: &[u8]) -> (Vec<&[u8]>, usize) {
    let mut args = Vec::with_capacity(8);
    let mut last_break = 0;
    let mut current_index = 0;
    for byte in bytes {
        if *byte == LF {
            if current_index - last_break > 1 {
                args.push(
                    &bytes[last_break..if bytes.get(current_index - 1) == Some(&CR) {
                        current_index - 1
                    } else {
                        current_index
                    }],
                );
            }
            break;
        }
        if *byte == SPACE && current_index - last_break > 1 {
            args.push(&bytes[last_break..current_index]);
        }
        current_index += 1;
        if *byte == SPACE {
            last_break = current_index;
        }
    }
    // Plus one, since loop breaks before
    (args, current_index + 1)
}
pub fn extension_args(bytes: &[u8]) -> (Vec<&[u8]>, usize) {
    if bytes.starts_with(EXTENSION_PREFIX) {
        parse_args(&bytes[EXTENSION_PREFIX.len()..])
    } else {
        (Vec::new(), 0)
    }
}
