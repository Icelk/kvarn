//! Parsing utilities and constants for Kvarn extensions.

use crate::{
    chars::{AMPERSAND, BANG, CR, LF, PIPE, SPACE},
    str, Arc, Bytes, Debug,
};

/// Magic number for [`Present`](https://kvarn.org/extensions/#present) extension.
///
/// `!> `
pub const PRESENT_INTERNAL_PREFIX: &[u8] = &[BANG, PIPE, SPACE];
/// Separator between [`Present`](https://kvarn.org/extensions/#present) extensions.
///
/// ` &> `
pub const PRESENT_INTERNAL_AND: &[u8] = &[SPACE, AMPERSAND, PIPE, SPACE];

#[derive(Debug)]
struct PresentExtensionPosData {
    name_start: usize,
    name_len: usize,

    arg_start: usize,
    arg_len: usize,
}
impl PresentExtensionPosData {
    fn from_name_and_arg(name: (usize, usize), arg: (usize, usize)) -> Self {
        Self {
            name_start: name.0,
            name_len: name.1,
            arg_start: arg.0,
            arg_len: arg.1,
        }
    }
    fn get_name(&self) -> (usize, usize) {
        (self.name_start, self.name_len)
    }
    fn get_arg(&self) -> (usize, usize) {
        (self.arg_start, self.arg_len)
    }
}

/// The [`Present`](https://kvarn.org/extensions/#present) extensions parsed from a file containing them.
#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Clone)]
#[must_use]
pub struct PresentExtensions {
    data: Bytes,
    extensions: Arc<Vec<PresentExtensionPosData>>,
    data_start: usize,
}
impl PresentExtensions {
    /// Parses a file to create a representation of the [`Present`](https://kvarn.org/extensions/#present) extensions in it.
    ///
    /// `data` should start with [`PRESENT_INTERNAL_PREFIX`], as all present extension files should.
    pub fn new(data: Bytes) -> Option<Self> {
        let mut extensions_args =
            Vec::with_capacity(
                data.iter()
                    .fold(1, |acc, byte| if *byte == SPACE { acc + 1 } else { acc }),
            );

        if !data.starts_with(PRESENT_INTERNAL_PREFIX)
            || data[PRESENT_INTERNAL_PREFIX.len()..].starts_with(PRESENT_INTERNAL_AND)
        {
            return None;
        }
        let mut start = PRESENT_INTERNAL_PREFIX.len();
        let mut last_name = None;
        let mut has_cr = false;
        for (pos, byte) in data.iter().enumerate().skip(3) {
            if start > pos {
                continue;
            }
            let byte = *byte;

            if byte == SPACE || byte == CR || byte == LF {
                if str::from_utf8(&data[start..pos]).is_err() {
                    return None;
                }
                let len = pos - start;
                let span = (start, len);

                // We have to borrow same mutably, which isn't possible in closures.
                #[allow(clippy::option_if_let_else)]
                if let Some(name) = last_name {
                    extensions_args.push(PresentExtensionPosData::from_name_and_arg(name, span));
                } else {
                    last_name = Some((start, len));
                    extensions_args.push(PresentExtensionPosData::from_name_and_arg(span, span));
                }
                if byte == CR {
                    has_cr = true;
                }
                if byte == LF {
                    return Some(Self {
                        data,
                        extensions: Arc::new(extensions_args),
                        data_start: pos + if has_cr { 2 } else { 1 },
                    });
                }
                start = if data[pos..].starts_with(PRESENT_INTERNAL_AND) {
                    last_name = None;
                    pos + PRESENT_INTERNAL_AND.len()
                } else {
                    pos + 1
                };
            }
        }

        None
    }
    /// Creates an empty representation of [`Present`](https://kvarn.org/extensions/#present) extensions
    pub fn empty() -> Self {
        Self {
            data: Bytes::new(),
            extensions: Arc::new(Vec::new()),
            data_start: 0,
        }
    }
    /// Gets an iterator of self.
    ///
    /// Clones the inner data.
    #[inline]
    pub fn iter(&self) -> PresentExtensionsIter {
        PresentExtensionsIter {
            data: Self::clone(self),
            index: 0,
        }
    }
    /// Returns the start of the document data, after all extensions and their arguments.
    #[inline]
    pub fn data_start(&self) -> usize {
        self.data_start
    }
}
impl IntoIterator for PresentExtensions {
    type Item = PresentArguments;
    type IntoIter = PresentExtensionsIter;
    fn into_iter(self) -> Self::IntoIter {
        PresentExtensionsIter {
            data: self,
            index: 0,
        }
    }
}
/// An iterator of [`PresentArguments`] from [`PresentExtensions`]
#[derive(Debug)]
pub struct PresentExtensionsIter {
    data: PresentExtensions,
    index: usize,
}
impl Iterator for PresentExtensionsIter {
    type Item = PresentArguments;
    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let start = self.index;
        if start == self.data.extensions.len() {
            return None;
        }
        let name = self.data.extensions[start].get_name();

        let iter = self.data.extensions[start + 1..].iter();

        for current in iter {
            self.index += 1;
            if current.get_name() != name {
                break;
            }
        }
        // Cannot change name ↑ on last item; the end of each *peeks* forward one. If it's next to the end, add one.
        if self.index + 1 == self.data.extensions.len() {
            self.index += 1;
        };
        Some(PresentArguments {
            data: PresentExtensions::clone(&self.data),
            data_index: start,
            len: self.index - start,
        })
    }
}
/// The arguments and name of a single [`Present`](https://kvarn.org/extensions/#present) extension.
#[derive(Debug)]
#[must_use]
pub struct PresentArguments {
    data: PresentExtensions,
    data_index: usize,
    len: usize,
}
impl PresentArguments {
    /// Creates an empty representation of [`Present`](https://kvarn.org/extensions/#present) arguments
    #[inline]
    pub fn empty() -> Self {
        Self {
            data: PresentExtensions::empty(),
            data_index: 0,
            len: 0,
        }
    }
    /// Gets the name of the extension.
    #[inline]
    pub fn name(&self) -> &str {
        // .1 and .0 should be the same; the name of (usize, usize) should have the same name as it's first argument.
        let (start, len) = self.data.extensions[self.data_index].get_name();
        // safe, because we checked for str in creation of [`PresentExtensions`].
        unsafe { str::from_utf8_unchecked(&self.data.data[start..start + len]) }
    }
    /// Returns an iterator of the arguments as [`prim@str`]s.
    #[inline]
    pub fn iter(&self) -> PresentArgumentsIter<'_> {
        PresentArgumentsIter {
            data: &self.data,
            data_index: self.data_index,
            back_index: self.len,
            index: 1,
        }
    }
}
/// An iterator of [`prim@str`] for the arguments in [`PresentArguments`]
#[derive(Debug)]
pub struct PresentArgumentsIter<'a> {
    data: &'a PresentExtensions,
    data_index: usize,
    back_index: usize,
    index: usize,
}
impl<'a> Iterator for PresentArgumentsIter<'a> {
    type Item = &'a str;
    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.index == self.back_index {
            return None;
        }
        let (start, len) = self.data.extensions[self.data_index + self.index].get_arg();
        self.index += 1;
        // Again, safe because we checked for str in creation of [`PresentExtensions`].
        Some(unsafe { str::from_utf8_unchecked(&self.data.data[start..start + len]) })
    }
}
impl<'a> DoubleEndedIterator for PresentArgumentsIter<'a> {
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.index == self.back_index {
            return None;
        }
        let (start, len) = self.data.extensions[self.data_index + self.back_index - 1].get_arg();
        self.back_index -= 1;
        // Again, safe because we checked for str in creation of [`PresentExtensions`].
        Some(unsafe { str::from_utf8_unchecked(&self.data.data[start..start + len]) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn basic() {
        let file = "\
!> tmpl standard.html md.html &> allow-ips 10.0.0.16 &>
File's contents.
";
        let mut extensions = PresentExtensions::new(Bytes::from_static(file.as_bytes()))
            .unwrap()
            .into_iter();
        {
            let extension = extensions.next().unwrap();
            assert_eq!(extension.name(), "tmpl");
            let mut arguments = extension.iter();
            assert_eq!(arguments.next(), Some("standard.html"));
            assert_eq!(arguments.next(), Some("md.html"));
            assert_eq!(arguments.next(), None);
        }
        {
            let extension = extensions.next().unwrap();
            assert_eq!(extension.name(), "allow-ips");
            let mut arguments = extension.iter();
            assert_eq!(arguments.next(), Some("10.0.0.16"));
            assert_eq!(arguments.next(), Some("&>"));
            assert_eq!(arguments.next(), None);
        }
        assert!(extensions.next().is_none());
    }
    #[test]
    #[should_panic]
    fn failing() {
        let file = "\
!>  tmpl standard.html  md.html  &>
File's contents.
";
        let mut extensions = PresentExtensions::new(Bytes::from_static(file.as_bytes()))
            .unwrap()
            .into_iter();
        {
            let extension = extensions.next().unwrap();
            assert_eq!(extension.name(), "tmpl");
            let mut arguments = extension.iter();
            assert_eq!(arguments.next(), Some("standard.html"));
            assert_eq!(arguments.next(), Some("md.html"));
            assert_eq!(arguments.next(), None);
        }
        assert!(extensions.next().is_none());
    }
    #[test]
    fn weird() {
        let file = "\
!>  tmpl standard.html  md.html  &>
File's contents.
";
        let mut extensions = PresentExtensions::new(Bytes::from_static(file.as_bytes()))
            .unwrap()
            .into_iter();
        {
            let extension = extensions.next().unwrap();
            assert_eq!(extension.name(), "");
            let mut arguments = extension.iter();
            assert_eq!(arguments.next(), Some("tmpl"));
            assert_eq!(arguments.next(), Some("standard.html"));
            assert_eq!(arguments.next(), Some(""));
            assert_eq!(arguments.next(), Some("md.html"));
            assert_eq!(arguments.next(), Some(""));
            assert_eq!(arguments.next(), Some("&>"));
            assert_eq!(arguments.next(), None);
        }
        assert!(extensions.next().is_none());
    }
}
