use kvarn::prelude::*;

/// `eq` must already have the mask applied.
fn eq_byte(input: u8, eq: u8, mask: u8) -> bool {
    input & mask == eq
}

#[derive(Debug)]
struct AbsolutePathIter<'a> {
    data: &'a [u8],
    last_was_illegal: bool,
    invalid: u8,
}
impl<'a> AbsolutePathIter<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            last_was_illegal: false,
            invalid: 0,
        }
    }
    /// [`None`] means it's illegal
    fn quote_illegal(&self, data: &[u8], final_byte: u8) -> Option<usize> {
        let mut last_was_slash = false;
        let mut ending = 0;
        for byte in data {
            if *byte == final_byte {
                break;
            }
            match *byte {
                b'\\' | b'*' | b'\n' | b'$' | b'{' | b'}' | b':' => {
                    return None;
                }
                b'/' if last_was_slash => return None,
                b'/' if !last_was_slash => last_was_slash = true,
                _ if last_was_slash => last_was_slash = false,
                _ => {}
            }
            ending += 1;
        }
        Some(ending)
    }
    fn next_quote(&mut self) -> Option<(&'a [u8], &'a [u8], usize)> {
        for (pos, byte) in self.data.iter().copied().enumerate() {
            // Handle non ascii characters
            if self.invalid > 0 {
                self.invalid -= 1;
                continue;
            }
            if eq_byte(byte, 0b11000000, 0b11100000) {
                self.invalid = 1;
            }
            if eq_byte(byte, 0b11100000, 0b11110000) {
                self.invalid = 2;
            }
            if eq_byte(byte, 0b11110000, 0b11111000) {
                self.invalid = 3;
            }

            if !self.last_was_illegal
                && (byte == b'"' || byte == b'\'')
                && self.data.get(pos + 1) == Some(&b'/')
            {
                let quote = &self.data[pos + 1..];
                let ending = self.quote_illegal(quote, byte);
                if let Some(ending) = ending {
                    let quote = &quote[..ending];
                    if !quote.is_empty() {
                        let before = &self.data[..=pos];
                        // + 2 to take in to account the quotes
                        return Some((quote, before, pos + 1 + ending + 1));
                    }
                }
            }

            self.last_was_illegal = matches!(byte, b'/' | b')' | b':');
        }
        None
    }
}
impl<'a> Iterator for AbsolutePathIter<'a> {
    type Item = IterItem<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        match self.data.is_empty() {
            true => None,
            false => match self.next_quote() {
                None => {
                    let last = self.data;
                    self.data = &[];
                    Some(IterItem::Last(last))
                }
                Some((path, before, advance)) => {
                    self.data = &self.data[advance..];
                    Some(IterItem::Path { path, before })
                }
            },
        }
    }
}

enum IterItem<'a> {
    Path { path: &'a [u8], before: &'a [u8] },
    Last(&'a [u8]),
}

/// Appends `prefix` to all absolute URL occurrences, to point the new page to the public endpoint.
pub fn absolute(body: &[u8], mut prefix: &str) -> BytesMut {
    use bytes::BufMut;

    if let Some(trimmed_prefix) = prefix.strip_suffix('"') {
        prefix = trimmed_prefix;
    }

    let mut buffer = BytesMut::with_capacity(body.len() + 5 * prefix.len());
    let iter = AbsolutePathIter::new(body);
    for item in iter {
        match item {
            IterItem::Last(last) => {
                buffer.extend_from_slice(last);
            }
            IterItem::Path { path, before } => {
                buffer.extend_from_slice(before);
                buffer.extend_from_slice(prefix.as_bytes());
                buffer.extend_from_slice(path);
                buffer.put_u8(b'"');
            }
        }
    }
    buffer
}
