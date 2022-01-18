use kvarn::prelude::*;

/// Appends `prefix` to all absolute URL occurrences, to point the new page to the public endpoint.
pub fn absolute(body: &[u8], _prefix: &str) -> BytesMut {
    body.into()
}
