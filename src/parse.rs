use crate::prelude::*;

#[derive(Debug)]
pub enum ParseError {
    NoPath,
    HTTP(http::Error),
    Io(io::Error),
}

#[derive(Debug)]
pub struct ValueQualitySet<'a> {
    pub value: &'a str,
    pub quality: f32,
}
impl PartialEq for ValueQualitySet<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}
impl PartialEq<str> for ValueQualitySet<'_> {
    fn eq(&self, other: &str) -> bool {
        self.value == other
    }
}

pub fn format_list_header(header: &str) -> Vec<ValueQualitySet> {
    let elements = header
        .chars()
        .fold(1, |acc, byte| if byte == ',' { acc + 1 } else { acc });
    let mut list = Vec::with_capacity(elements);

    let mut start_byte = 0;
    let mut end_byte = 0;
    let mut in_quality = false;
    let mut previous_was_q = false;
    let mut quality_start_byte = 0;
    for (position, byte) in header.char_indices() {
        if byte == ' ' {
            continue;
        }

        if in_quality && quality_start_byte == 0 {
            match byte {
                '0' | '1' | '2' | '3' | '4' | '5' | '6' | '7' | '8' | '9' | '.' => {
                    quality_start_byte = position;
                }
                _ => {}
            }
        }

        if byte == ';' && !in_quality {
            end_byte = position;
            in_quality = true;
        }
        if in_quality {
            if byte == '=' && previous_was_q {
                quality_start_byte = position + 1;
            }
            previous_was_q = if byte == 'q' { true } else { false }
        }

        if byte == ',' {
            let quality = match header
                .get(quality_start_byte..position)
                .and_then(|quality| quality.parse().ok())
            {
                Some(quality) => quality,
                None => 1.0,
            };
            match header.get(start_byte..if end_byte == 0 { position } else { end_byte }) {
                Some(accept) => list.push(ValueQualitySet {
                    value: accept,
                    quality,
                }),
                None => {}
            }
            quality_start_byte = 0;
            end_byte = 0;
            start_byte = if header.as_bytes().get(position + 1) == Some(&SPACE) {
                position + 2
            } else {
                position + 1
            };
            in_quality = false;
        }
    }
    // Last, when reaches EOF
    let quality = match header
        .get(quality_start_byte..)
        .and_then(|quality| quality.parse().ok())
    {
        Some(quality) => quality,
        None => 1.0,
    };
    match header.get(start_byte..) {
        Some(accept) => list.push(ValueQualitySet {
            value: accept,
            quality,
        }),
        None => {}
    }
    list
}
pub fn format_query(query: &str) -> HashMap<&str, &str> {
    let elements = query
        .chars()
        .fold(1, |acc, byte| if byte == '&' { acc + 1 } else { acc });
    let mut map = HashMap::with_capacity(elements);

    let mut pair_start = 0;
    let mut value_start = 0;
    for (position, byte) in query.char_indices() {
        match byte {
            '=' => {
                value_start = position;
            }
            '&' => {
                let key = query.get(pair_start..value_start);
                let value = query.get(value_start + 1..position);

                if key.is_some() && value.is_some() {
                    map.insert(key.unwrap(), value.unwrap());
                }

                pair_start = position + 1;
            }
            _ => {}
        }
    }
    {
        let key = query.get(pair_start..value_start);
        let value = query.get(value_start + 1..);

        if key.is_some() && value.is_some() {
            map.insert(key.unwrap(), value.unwrap());
        }
    }
    map
}

/// Will convert an `&str` path to a `PathBuf` using other paramaters.
///
/// `base_path` corresponds to the the first segment(s) of the path.
/// `folder_default` sets the file if pointed to a folder
/// `extension_default` sets the file extension if pointed to a file with no extension (e.g. `index.`)
///
/// The returned path will be formatted as follows `<base_path>/public/<path>[.<extension_default>][/<folder_default>]`
///
/// # Panics
/// // Will panic if `path.is_empty()`, since it checks the last byte
/// This is checked before trying to access bytes, and returns `None` if the assert fails.
pub fn convert_uri(
    path: &str,
    base_path: &Path,
    folder_default: &str,
    extension_default: &str,
) -> PathBuf {
    assert_eq!(path.as_bytes()[0], FORWARD_SLASH);
    // Unsafe is ok, since we remove the first byte of a string that is always `/`, occupying exactly one byte.
    let stripped_path = unsafe { str::from_utf8_unchecked(&path.as_bytes()[1..]) };

    let mut buf = PathBuf::with_capacity(
        base_path.as_os_str().len() + 6 /* "public".len() */ + path.len() + cmp::max(folder_default.len(), extension_default.len()),
    );
    buf.push(base_path);
    buf.push("public");
    buf.push(stripped_path);

    // The path is guaranteed to be at least one byte long
    let last_byte = path.as_bytes()[path.len() - 1];

    if last_byte == FORWARD_SLASH {
        buf.push(folder_default);
    } else if last_byte == PERIOD {
        buf.set_extension(extension_default);
    };
    buf
}

pub fn parse_version(bytes: &[u8]) -> Option<Version> {
    Some(match &bytes[..] {
        b"HTTP/0.9" => Version::HTTP_09,
        b"HTTP/1.0" => Version::HTTP_10,
        b"HTTP/1.1" => Version::HTTP_11,
        b"HTTP/2" => Version::HTTP_2,
        b"HTTP/3" => Version::HTTP_3,
        _ => return None,
    })
}
