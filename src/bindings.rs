use crate::prelude::{internals::*, *};
use http::Request;

type Binding = dyn Fn(&mut Vec<u8>, &Request<&[u8]>, &mut FsCache) -> (utility::ContentType, Cached)
    + Send
    + Sync;

/// Function bindings to have fast dynamic pages.
///
/// Functions can be associated with URLs by calling the `bind` function.
pub struct FunctionBindings {
    page_map: HashMap<String, Box<Binding>>,
    dir_map: HashMap<String, Box<Binding>>,
}
impl FunctionBindings {
    /// Creates a new, empty set of bindings.
    ///
    /// Use `bind` to populate it
    #[inline]
    pub fn new() -> Self {
        FunctionBindings {
            page_map: HashMap::new(),
            dir_map: HashMap::new(),
        }
    }
    /// Binds a function to a path. Case sensitive.
    /// Don't forget to handle methods other than `GET`. `HEAD` is implemented in the backend.
    ///
    /// Fn needs to return a tuple with the content type (e.g. `text/html`), and whether the return value should be cached or not.
    /// # Examples
    /// ```
    /// use arktis::{FunctionBindings, ContentType, write_error, Cached};
    ///
    /// let mut bindings = FunctionBindings::new();
    ///
    /// bindings.bind_page("/test", |buffer, request, _| {
    ///    buffer.extend(b"<h1>Welcome to my site!</h1> You are calling: ".iter());
    ///    buffer.extend(format!("{}", request.uri()).as_bytes());
    ///
    ///    (ContentType::Html, Cached::Static)
    /// });
    /// bindings.bind_page("/throw_500", |mut buffer, _, storage| {
    ///   write_error(&mut buffer, 500, storage);
    ///
    ///   (ContentType::Html, Cached::Changing)
    /// });
    /// ```
    #[inline]
    pub fn bind_page<F>(&mut self, path: &str, callback: F)
    where
        F: Fn(&mut Vec<u8>, &Request<&[u8]>, &mut FsCache) -> (utility::ContentType, Cached)
            + 'static
            + Send
            + Sync,
    {
        self.page_map.insert(path.to_owned(), Box::new(callback));
    }
    /// Unbinds a function from a page.
    ///
    /// Returns `None` if path wasn't bind.
    #[inline]
    pub fn unbind_page(&mut self, path: &str) -> Option<()> {
        self.page_map.remove(path).and(Some(()))
    }

    /// Binds a function to a directory; if the requests path starts with any entry, it gets directed to the associated function. Case sensitive.
    /// Don't forget to handle methods other than `GET`. `HEAD` is implemented in the backend.
    ///
    /// Fn needs to return a tuple with the content type (e.g. `text/html`), and whether the return value should be cached or not.
    /// # Examples
    /// ```
    /// use arktis::{FunctionBindings, ContentType, Cached};
    /// use http::Method;
    ///
    /// let mut bindings = FunctionBindings::new();
    ///
    /// bindings.bind_dir("/api/v1", |buffer, request, _| {
    ///    buffer.extend(b"<h1>Welcome to my <i>new</i> <b>API</b>!</h1> You are calling: ".iter());
    ///    buffer.extend(format!("{}", request.uri()).as_bytes());
    ///
    ///    (ContentType::Html, Cached::Dynamic)
    /// });
    /// ```
    #[inline]
    pub fn bind_dir<F>(&mut self, path: &str, callback: F)
    where
        F: Fn(&mut Vec<u8>, &Request<&[u8]>, &mut FsCache) -> (utility::ContentType, Cached)
            + 'static
            + Send
            + Sync,
    {
        self.dir_map.insert(path.to_owned(), Box::new(callback));
    }
    /// Unbinds a function from a directory.
    ///
    /// Returns None if path wasn't bind.
    #[inline]
    pub fn unbind_dir(&mut self, path: &str) -> Option<()> {
        self.dir_map.remove(path).and(Some(()))
    }

    /// Gets the function associated with the URL, if there is one.
    #[inline]
    pub fn get_binding(&self, path: &str) -> Option<&Box<Binding>> {
        self.page_map.get(path).or_else(|| {
            for (binding_path, binding_fn) in self.dir_map.iter() {
                if path.starts_with(binding_path.as_str()) {
                    return Some(binding_fn);
                }
            }
            None
        })
    }
}
impl fmt::Debug for FunctionBindings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FunctionBindings {{ page_map: ")?;
        f.debug_map()
            .entries(
                self.page_map
                    .iter()
                    .map(|(key, _)| (key, "boxed internal function")),
            )
            .finish()?;
        write!(f, ", dir_map: ")?;
        f.debug_map()
            .entries(
                self.dir_map
                    .iter()
                    .map(|(key, _)| (key, "boxed internal function")),
            )
            .finish()?;
        write!(f, " }}")
    }
}
