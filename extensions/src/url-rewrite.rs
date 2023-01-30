use kvarn::prelude::*;

use url_crawl::{IterItem, LinkIter};

/// Appends `prefix` to all absolute URL occurrences, to point the new page to the public endpoint.
pub fn absolute(body: &[u8], mut prefix: &str) -> BytesMut {
    use bytes::BufMut;

    if let Some(trimmed_prefix) = prefix.strip_suffix('"') {
        prefix = trimmed_prefix;
    }

    let mut buffer = BytesMut::with_capacity(body.len() + 5 * prefix.len());
    let iter = LinkIter::new_with_aboslute_paths_filter(body);
    for item in iter {
        match item {
            IterItem::Last(last) => {
                buffer.extend_from_slice(last);
            }
            IterItem::Path {
                path,
                before,
                quote_type,
            } => {
                buffer.extend_from_slice(before);
                buffer.extend_from_slice(prefix.as_bytes());
                buffer.extend_from_slice(path);
                buffer.put_u8(quote_type.as_byte());
            }
        }
    }
    buffer
}
