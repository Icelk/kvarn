use crate::prelude::{internals::*, *};

pub const EXTENSION_PREFIX: &[u8] = &[BANG, PIPE];
pub const EXTENSION_AND: &[u8] = &[AMPERSAND, PIPE];

pub(crate) mod parse {
    use super::*;

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

#[derive(Debug, Clone)]
pub struct ExtensionMap {
    name: HashMap<&'static str, ExtensionPointer>,
    extensions: HashMap<&'static str, ExtensionPointer>,
}
impl ExtensionMap {
    pub fn get_name<'a, 'b>(&'a mut self, name: &'b str) -> Option<&'a mut Box<dyn Ext + Send>> {
        match self.name.get(name) {
            Some(pointer) => match pointer {
                ExtensionPointer::Data(..) => {
                    self.name.get_mut(name).map(|data| data.assume_data())
                }
                ExtensionPointer::ReferenceToName(pointer) => {
                    let pointer = *pointer;
                    self.name
                        .get_mut(pointer)
                        .map(|pointer| pointer.assume_data())
                }
                ExtensionPointer::ReferenceToFE(..) => {
                    unreachable!("No references to file extensions should be made from name map")
                }
            },
            None => None,
        }
    }
    pub fn get_file_extension<'a, 'b>(
        &'a mut self,
        file_extension: &'b str,
    ) -> Option<&'a mut Box<dyn Ext + Send>> {
        match self.extensions.get(file_extension) {
            Some(pointer) => match pointer {
                ExtensionPointer::Data(..) => self
                    .extensions
                    .get_mut(file_extension)
                    .map(|data| data.assume_data()),
                ExtensionPointer::ReferenceToName(pointer) => {
                    let pointer = *pointer;
                    self.name
                        .get_mut(pointer)
                        .map(|pointer| pointer.assume_data())
                }
                ExtensionPointer::ReferenceToFE(pointer) => {
                    let pointer = *pointer;
                    self.extensions
                        .get_mut(pointer)
                        .map(|pointer| pointer.assume_data())
                }
            },
            None => None,
        }
    }
}
enum ExtensionPointer {
    ReferenceToName(&'static str),
    ReferenceToFE(&'static str),
    Data(Box<dyn Ext + Send>),
}
impl ExtensionPointer {
    pub fn assume_data(&mut self) -> &mut Box<dyn Ext + Send> {
        match self {
            Self::Data(data) => data,
            _ => panic!("ExtensionPointer does not point to data!"),
        }
    }
}
impl fmt::Debug for ExtensionPointer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ExtensionPointer(")?;
        match self {
            ExtensionPointer::Data(..) => write!(f, "internal data)"),
            ExtensionPointer::ReferenceToName(name) | ExtensionPointer::ReferenceToFE(name) => {
                write!(f, "points to '{}')", name)
            }
        }
    }
}
impl Clone for ExtensionPointer {
    fn clone(&self) -> Self {
        match self {
            Self::Data(data) => Self::Data(data.clone_to_uninit()),
            Self::ReferenceToName(name) => Self::ReferenceToName(name),
            Self::ReferenceToFE(name) => Self::ReferenceToFE(name),
        }
    }
}
#[derive(Debug)]
pub struct Extensions {
    vec: Vec<BoundExtension>,
}
impl Extensions {
    pub fn new() -> Self {
        Self {
            vec: Vec::with_capacity(16),
        }
    }
    pub fn extend<
        T: fmt::Debug,
        N: Fn() -> T + 'static + Send + Sync,
        R: Fn(&mut T, RequestData) -> () + 'static + Send + Sync,
    >(
        &mut self,
        name_aliases: &'static [&'static str],
        extension_aliases: &'static [&'static str],
        new_fn: &'static N,
        run_fn: &'static R,
    ) where
        T: 'static + Send,
    {
        self.vec.push(BoundExtension {
            ext: Extension::new(new_fn, run_fn),
            extension_aliases: name_aliases,
            file_extension_aliases: extension_aliases,
        })
    }
    /// # Panics
    /// The extension must contain at least one binding, to a file or extension name.
    pub fn add_extension(&mut self, ext: BoundExtension) {
        if ext.extension_aliases.is_empty() && ext.file_extension_aliases.is_empty() {
            panic!("Extension must have bindings!");
        }
        self.vec.push(ext);
    }
    pub fn init_all(&mut self) {
        for extension in self.vec.iter_mut() {
            extension.ext.init();
        }
    }
    pub fn get_maps(self) -> ExtensionMap {
        let mut name_map = HashMap::new();
        let mut extension_map = HashMap::new();

        for extension in self.vec.into_iter() {
            let is_in_extensions_map = extension.extension_aliases.is_empty();
            let mut fe_iter = extension.file_extension_aliases.iter();
            let mut name_iter = extension.extension_aliases.iter();
            let first_value = if is_in_extensions_map {
                let value = *fe_iter.next().unwrap();
                extension_map.insert(value, ExtensionPointer::Data(extension.ext));
                value
            } else {
                let value = *name_iter.next().unwrap();
                name_map.insert(value, ExtensionPointer::Data(extension.ext));
                value
            };
            for extension_binding in fe_iter {
                extension_map.insert(
                    extension_binding,
                    if is_in_extensions_map {
                        ExtensionPointer::ReferenceToFE(first_value)
                    } else {
                        ExtensionPointer::ReferenceToName(first_value)
                    },
                );
            }
            for extension_binding in name_iter {
                // If is_in_extensions_map check isn't needed; if name_iter has one item, all references goes there!
                name_map.insert(
                    extension_binding,
                    ExtensionPointer::ReferenceToName(first_value),
                );
            }
        }

        ExtensionMap {
            name: name_map,
            extensions: extension_map,
        }
    }
}
impl Clone for Extensions {
    fn clone(&self) -> Self {
        Self {
            vec: self.vec.iter().map(|old| old.clone()).collect(),
        }
    }
}
#[derive(Debug)]
pub struct BoundExtension {
    pub ext: Box<dyn Ext + Send>,
    pub extension_aliases: &'static [&'static str],
    pub file_extension_aliases: &'static [&'static str],
}
impl BoundExtension {
    pub fn into_ext(self) -> Box<dyn Ext + Send> {
        self.ext
    }
}
impl Clone for BoundExtension {
    fn clone(&self) -> Self {
        Self {
            ext: self.ext.clone_to_uninit(),
            extension_aliases: self.extension_aliases,
            file_extension_aliases: self.file_extension_aliases,
        }
    }
}
#[derive(Debug)]
pub struct RequestData<'a> {
    pub address: &'a net::SocketAddr,
    pub response: &'a mut ByteResponse,
    pub content_start: usize,
    pub cached: &'a mut Cached,
    pub args: Vec<String>,
    pub storage: &'a mut Storage,
    pub request: &'a http::Request<&'a [u8]>,
    pub raw_request: &'a [u8],
    pub path: &'a PathBuf,
    pub content_type: &'a mut utility::ContentType,
    pub close: &'a connection::ConnectionHeader,
}

pub trait Ext: fmt::Debug {
    /// # Safety
    /// `init` must be called before this function, else the `fn` will get an unititalized value.
    ///
    /// # Examples
    /// Correct usage:
    /// ```no_run
    /// use kvarn::extension_helper::{Extension, Ext};
    ///
    /// let mut ext = Extension::new(&|| 9, &|value, _| println!("Value: {}", value));
    /// ext.init();
    /// # let request_data = unsafe { std::mem::MaybeUninit::uninit().assume_init() };
    /// unsafe { ext.run(request_data) };
    /// ```
    /// *Incorrect* usage:
    /// ```no_run
    /// use kvarn::extension_helper::{Extension, Ext};
    ///
    /// let mut ext = Extension::new(&|| 9, &|value, _| println!("Value: {}", value));
    /// # let request_data = unsafe { std::mem::MaybeUninit::uninit().assume_init() };
    /// unsafe { ext.run(request_data) };
    /// ```
    unsafe fn run(&mut self, data: RequestData);
    fn init(&mut self);
    /// # Safety
    /// Must be initialized (by calling `init`) before calling this function. Else, it will perform the `drop` on a random memory address.
    ///
    /// # Examples
    /// Correct usage:
    /// ```
    /// use kvarn::extension_helper::{Extension, Ext};
    ///
    /// let mut ext = Extension::new(&|| 9, &|value, _| println!("Value: {}", value));
    /// ext.init();
    /// unsafe { ext.uninit() };
    /// ```
    /// *Incorrect* usage:
    /// ```no_run
    /// use kvarn::extension_helper::{Extension, Ext};
    ///
    /// let mut ext = Extension::new(&|| "A str!", &|value, _| println!("Value: {}", value));
    /// unsafe { ext.uninit() };
    /// ```
    unsafe fn uninit(self: Box<Self>);
    fn clone_to_uninit(&self) -> Box<dyn Ext + Send>;
}
impl<T: Send + fmt::Debug> Ext for Extension<T> {
    unsafe fn run(&mut self, data: RequestData) {
        (self.run_fn)(self.data.as_mut_ptr().as_mut().unwrap(), data);
    }
    fn init(&mut self) {
        self.data = MaybeUninit::new((self.new_fn)());
    }
    unsafe fn uninit(self: Box<Self>) {
        drop(self.data.assume_init());
    }
    fn clone_to_uninit(&self) -> Box<dyn Ext + Send> {
        Box::new(self.clone())
    }
}
pub struct Extension<T: 'static> {
    data: MaybeUninit<T>,
    new_fn: &'static (dyn Fn() -> T + 'static + Send + Sync),
    run_fn: &'static (dyn Fn(&mut T, RequestData) -> () + 'static + Send + Sync),
}
impl<T: fmt::Debug> Extension<T> {
    pub fn new<
        N: Fn() -> T + 'static + Send + Sync,
        R: Fn(&mut T, RequestData) -> () + 'static + Send + Sync,
    >(
        new_fn: &'static N,
        run_fn: &'static R,
    ) -> Box<dyn Ext + Send>
    where
        T: 'static + Send,
    {
        Box::new(Self {
            data: MaybeUninit::uninit(),
            new_fn,
            run_fn,
        })
    }
}
impl<T: Send> Clone for Extension<T> {
    fn clone(&self) -> Self {
        Self {
            data: MaybeUninit::uninit(),
            new_fn: self.new_fn,
            run_fn: self.run_fn,
        }
    }
}
impl<T: fmt::Debug> fmt::Debug for Extension<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Extension<T> {{ data: {:?}, new_fn: &dyn Fn() -> T, run_fn: &dyn Fn(&mut T, RequestData) -> () }}",
            self.data
        )
    }
}
