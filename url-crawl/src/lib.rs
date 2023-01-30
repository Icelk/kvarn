/// Extracts the links from `html`.
/// This can be used to HTTP/2 push the linked resources.
///
/// Gets
/// - `<link>` nodes where `rel` != `preconnect`
/// - all nodes with a `src` attribute
///
/// ToDo: Add `background-image` and other css link detection
pub fn get_urls(html: &str) -> impl Iterator<Item = &str> {
    LinkIter::new_with_resource_filter(html.as_bytes()).filter_map(|item| match item {
        IterItem::Path { path, .. } => match std::str::from_utf8(path) {
            Ok(s) => Some(s),
            Err(err) => {
                log::error!("url-crawl return invalid utf8: {err}");
                None
            }
        },
        IterItem::Last(_) => None,
    })
}

pub mod filters {
    /// Used for url rewrite in reverse proxy
    pub fn absolute_path(data: &[u8], pos: usize) -> bool {
        data.get(pos + 1) == Some(&b'/')
    }
    /// Used to list resources to push in HTTP/2 push
    pub fn resource(data: &[u8], pos: usize) -> bool {
        // don't require tag contents
        let is_css = || data.get(pos.saturating_sub(22)..pos) == Some(b"background-image: url(");

        if data.get(pos.saturating_sub(1)) != Some(&b'=') {
            return is_css();
        }
        let tag_contents = {
            let tag_start = memchr::memrchr(b'<', &data[..pos]).unwrap_or(0);
            let tag = &data[tag_start..];
            let tag_len = memchr::memchr(b'>', tag);
            if let Some(tag_len) = tag_len {
                &data[tag_start..tag_len + tag_start]
            } else {
                &data[tag_start..]
            }
        };
        // require tag contents
        let is_source = || {
            data.get(pos.saturating_sub(5)..pos) == Some(b" src=")
                && memchr::memmem::find(tag_contents, b"loading=\"lazy\"").is_none()
                && memchr::memmem::find(tag_contents, b"loading='lazy'").is_none()
        };
        let is_link = || {
            // not `<link `, as some formatting tools put the next line right after
            // `<link`.
            // filter out all `<a>`s
            (data.get(pos.saturating_sub(6)..pos) == Some(b" href="))
                && tag_contents.starts_with(b"<link")
                && (memchr::memmem::find(tag_contents, b"rel=\"stylesheet\"").is_some()
                    || memchr::memmem::find(tag_contents, b"rel='stylesheet'").is_some()
                    || memchr::memmem::find(tag_contents, b"rel=\"modulepreload\"").is_some()
                    || memchr::memmem::find(tag_contents, b"rel='modulepreload'").is_some())
        };
        is_source() || is_link() || is_css()
    }
}

/// `eq` must already have the mask applied.
fn eq_byte(input: u8, eq: u8, mask: u8) -> bool {
    input & mask == eq
}

#[derive(Debug)]
pub struct LinkIter<'a> {
    data: &'a [u8],
    last_was_illegal: bool,
    invalid: u8,
    filter: fn(&'a [u8], usize) -> bool,
    interdomain_links: bool,
}
impl<'a> LinkIter<'a> {
    /// Filter is for determining whether or not a quote is a link. See [`filters`].
    /// `allow_interdomain_links` sets whether or not to allow links from other domains.
    pub fn new(
        data: &'a [u8],
        filter: fn(&'a [u8], usize) -> bool,
        allow_interdomain_links: bool,
    ) -> Self {
        Self {
            data,
            last_was_illegal: false,
            invalid: 0,
            filter,
            interdomain_links: allow_interdomain_links,
        }
    }
    pub fn new_with_aboslute_paths_filter(data: &'a [u8]) -> Self {
        Self::new(data, filters::absolute_path, false)
    }
    pub fn new_with_resource_filter(data: &'a [u8]) -> Self {
        Self::new(data, filters::resource, false)
    }
    /// [`None`] means it's illegal
    fn quote_illegal(&self, data: &[u8], final_byte: u8) -> Option<usize> {
        let mut last_was_slash = false;
        let mut ending = 0;
        for byte in data {
            if *byte == final_byte {
                break;
            }
            let illegal = if final_byte == b'`' {
                matches!(*byte, b'\\' | b'*' | b'\n')
            } else {
                matches!(*byte, b'\\' | b'*' | b'\n' | b'$' | b'{' | b'}')
            };
            if illegal {
                return None;
            }
            match *byte {
                b'/' if last_was_slash && !self.interdomain_links => return None,
                b'/' if !last_was_slash => last_was_slash = true,
                _ if last_was_slash => last_was_slash = false,
                _ => {}
            }
            ending += 1;
        }
        Some(ending)
    }
    fn next_quote(&mut self) -> Option<(&'a [u8], &'a [u8], usize, QuoteType)> {
        for (pos, byte) in self.data.iter().copied().enumerate() {
            // Handle non ascii characters
            if self.invalid > 0 {
                self.invalid -= 1;
                continue;
            }
            // How long the character is - skip non-ascii characters
            if eq_byte(byte, 0b11000000, 0b11100000) {
                self.invalid = 1;
                continue;
            }
            if eq_byte(byte, 0b11100000, 0b11110000) {
                self.invalid = 2;
                continue;
            }
            if eq_byte(byte, 0b11110000, 0b11111000) {
                self.invalid = 3;
                continue;
            }

            if !self.last_was_illegal
                && matches!(byte, b'"' | b'\'' | b'`')
                && (self.filter)(self.data, pos)
            {
                let quote_type = QuoteType::from_byte(byte).unwrap();
                let quote = &self.data[pos + 1..];
                let ending = self.quote_illegal(quote, byte);
                if let Some(ending) = ending {
                    if ending > 2 {
                        let quote = &quote[..ending];
                        if !quote.is_empty() {
                            let before = &self.data[..=pos];
                            // + 2 to take in to account the quotes
                            return Some((quote, before, pos + 1 + ending + 1, quote_type));
                        }
                    }
                }
            }

            self.last_was_illegal = matches!(byte, b'/' | b')' | b':' | b',' | b'|' | b'^');
        }
        None
    }
}
impl<'a> Iterator for LinkIter<'a> {
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
                Some((path, before, advance, quote_type)) => {
                    self.data = &self.data[advance..];
                    Some(IterItem::Path {
                        path,
                        before,
                        quote_type,
                    })
                }
            },
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum QuoteType {
    Single,
    Double,
    Backtick,
}
impl QuoteType {
    pub fn from_byte(b: u8) -> Option<Self> {
        Some(match b {
            b'"' => Self::Double,
            b'\'' => Self::Single,
            b'`' => Self::Backtick,
            _ => return None,
        })
    }
    pub fn as_byte(self) -> u8 {
        match self {
            Self::Single => b'\'',
            Self::Double => b'"',
            Self::Backtick => b'`',
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum IterItem<'a> {
    Path {
        path: &'a [u8],
        before: &'a [u8],
        quote_type: QuoteType,
    },
    Last(&'a [u8]),
}

#[cfg(test)]
mod tests {
    use crate::get_urls;

    #[test]
    fn basic_html() {
        let html = r#"
<html lang="en-GB">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=0.8, shrink-to-fit=no">
        <link rel="preconnect" href="https://fonts.gstatic.com">
        <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Roboto:400&;display=swap">
        <link rel="stylesheet" type="text/css" href="/style.css">
        <script src="/script.js" defer></script>
    </head>

    <body>
        <main style="text-align: center; background-image: url('/bg.png');">
            <a href="/posts/">Go to posts</a>
        </main>
    </body>
</html>"#;

        assert_eq!(
            get_urls(html).collect::<Vec<_>>(),
            &["/style.css", "/script.js", "/bg.png"]
        )
    }
}
