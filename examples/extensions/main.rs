pub struct Extension<T> {
    data: std::mem::MaybeUninit<T>,
    new_fn: Box<dyn Fn() -> T>,
    run_fn: Box<dyn Fn(&mut T) -> ()>,
}
impl<T> Extension<T> {
    pub fn new<N: Fn() -> T + 'static, R: Fn(&mut T) -> () + 'static>(
        new_fn: N,
        run_fn: R,
    ) -> Self {
        Self {
            data: std::mem::MaybeUninit::uninit(),
            new_fn: Box::new(new_fn),
            run_fn: Box::new(run_fn),
        }
    }
    pub fn new_box<'a, N: Fn() -> T + 'static, R: Fn(&mut T) -> () + 'static>(
        new_fn: N,
        run_fn: R,
    ) -> Box<dyn Ext>
    where
        T: 'static,
    {
        let new = Box::new(new_fn);
        Box::new(Self {
            data: std::mem::MaybeUninit::uninit(),
            new_fn: new,
            run_fn: Box::new(run_fn),
        })
    }
    pub unsafe fn run(&mut self) {
        (self.run_fn)(self.data.as_mut_ptr().as_mut().unwrap());
    }
    pub fn init(&mut self) {
        self.data = std::mem::MaybeUninit::new((self.new_fn)());
    }
}

pub trait Ext {
    unsafe fn run(&mut self);
    fn init(&mut self);
}
impl<T> Ext for Extension<T> {
    unsafe fn run(&mut self) {
        self.run();
    }
    fn init(&mut self) {
        self.init();
    }
}

pub fn init_all(extensions: &mut Vec<Box<dyn Ext>>) {
    for extension in extensions {
        extension.init();
    }
}
pub unsafe fn run_all(extensions: &mut Vec<Box<dyn Ext>>) {
    for extension in extensions {
        extension.run();
    }
}

fn main() {
    let mut extensions: Vec<Box<dyn Ext>> = Vec::new();

    extensions.push(Extension::new_box(|| 9, |value| println!("{}", value)));
    extensions.push(Extension::new_box(|| "hi!", |value| println!("{}", value)));

    init_all(&mut extensions);

    unsafe {
        run_all(&mut extensions);
    }
}
