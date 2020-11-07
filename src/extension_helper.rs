use crate::*;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct ExtensionMap {
    name: HashMap<&'static str, ExtensionPointer>,
    extensions: HashMap<&'static str, ExtensionPointer>,
}
impl ExtensionMap {
    pub fn get<'a, 'b>(
        &'a mut self,
        name: Option<&'b str>,
        file_extension: Option<&'b str>,
    ) -> Option<&'a mut Box<dyn Ext + Send>> {
        match name.and_then(|name| self.name.get(name)) {
            Some(pointer) => match pointer {
                ExtensionPointer::Data(..) => self
                    .name
                    .get_mut(name.unwrap())
                    .map(|data| data.assume_data()),
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
            None => match file_extension.and_then(|fe| self.extensions.get(fe)) {
                Some(pointer) => match pointer {
                    ExtensionPointer::Data(..) => self
                        .extensions
                        .get_mut(file_extension.unwrap())
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
            },
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
impl std::fmt::Debug for ExtensionPointer {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
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
pub struct Extensions {
    vec: Vec<BoundExtension>,
}
impl Extensions {
    pub fn new() -> Self {
        Self { vec: Vec::new() }
    }
    pub fn extend<
        T,
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

pub struct RequestData<'a> {
    pub response: &'a mut ByteResponse,
    pub content_start: usize,
    pub cached: &'a mut Cached,
    pub args: Vec<String>,
    pub storage: &'a mut Storage,
    pub request: &'a http::Request<&'a [u8]>,
    pub raw_request: &'a [u8],
    pub path: &'a PathBuf,
    pub content_type: &'a mut ContentType,
}

pub trait Ext {
    /// # Safety
    /// `init` must be called before this function, else the `fn` will get an unititalized value.
    ///
    /// # Examples
    /// Correct usage:
    /// ```no_run
    /// use arktis::extension_helper::{Extension, Ext};
    ///
    /// let mut ext = Extension::new(&|| 9, &|value, _| println!("Value: {}", value));
    /// ext.init();
    /// # let request_data = unsafe { std::mem::MaybeUninit::uninit().assume_init() };
    /// unsafe { ext.run(request_data) };
    /// ```
    /// *Incorrect* usage:
    /// ```no_run
    /// use arktis::extension_helper::{Extension, Ext};
    ///
    /// let mut ext = Extension::new(&|| 9, &|value, _| println!("Value: {}", value));
    /// # let request_data = unsafe { std::mem::MaybeUninit::uninit().assume_init() };
    /// unsafe { ext.run(request_data) };
    /// ```
    unsafe fn run(&mut self, data: RequestData);
    fn init(&mut self);
    /// # Safety
    /// Must be initialized (by calling `init`) before calling this function. Else, it will perform the `drop` on a random memory adress.
    ///
    /// # Examples
    /// Correct usage:
    /// ```
    /// use arktis::extension_helper::{Extension, Ext};
    ///
    /// let mut ext = Extension::new(&|| 9, &|value, _| println!("Value: {}", value));
    /// ext.init();
    /// unsafe { ext.uninit() };
    /// ```
    /// *Incorrect* usage:
    /// ```no_run
    /// use arktis::extension_helper::{Extension, Ext};
    ///
    /// let mut ext = Extension::new(&|| "A str!", &|value, _| println!("Value: {}", value));
    /// unsafe { ext.uninit() };
    /// ```
    unsafe fn uninit(self: Box<Self>);
    fn clone_to_uninit(&self) -> Box<dyn Ext + Send>;
}
impl<T: Send> Ext for Extension<T> {
    unsafe fn run(&mut self, data: RequestData) {
        (self.run_fn)(self.data.as_mut_ptr().as_mut().unwrap(), data);
    }
    fn init(&mut self) {
        self.data = std::mem::MaybeUninit::new((self.new_fn)());
    }
    unsafe fn uninit(self: Box<Self>) {
        drop(self.data.assume_init());
    }
    fn clone_to_uninit(&self) -> Box<dyn Ext + Send> {
        Box::new(self.clone())
    }
}
pub struct Extension<T: 'static> {
    data: std::mem::MaybeUninit<T>,
    new_fn: &'static (dyn Fn() -> T + 'static + Send + Sync),
    run_fn: &'static (dyn Fn(&mut T, RequestData) -> () + 'static + Send + Sync),
}
impl<T> Extension<T> {
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
            data: std::mem::MaybeUninit::uninit(),
            new_fn: new_fn,
            run_fn: run_fn,
        })
    }
}
impl<T: Send> Clone for Extension<T> {
    fn clone(&self) -> Self {
        Self {
            data: std::mem::MaybeUninit::uninit(),
            new_fn: self.new_fn,
            run_fn: self.run_fn,
        }
    }
}
