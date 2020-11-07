use crate::chars::*;

pub const EXTENSION_PREFIX: &[u8] = &[BANG, PIPE];
pub const EXTENSION_AND: &[u8] = &[AMPERSAND, PIPE];

fn parse_args(bytes: &[u8]) -> (Vec<Vec<String>>, usize) {
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
        parse_args(&bytes[EXTENSION_PREFIX.len()..])
    } else {
        (Vec::new(), 0)
    }
}
