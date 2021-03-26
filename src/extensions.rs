use crate::*;
use bytes::{Bytes, BytesMut};
use comprash::{ClientCachePreference, CompressPreference, ServerCachePreference};
use http::Uri;
use std::future::Future;

pub type Extension<A, R> = Box<dyn Fn(A) -> &'static dyn Future<Output = R>>;
pub type FsCache = ();
pub type Request<S> = http::Request<application::Body<S>>;
pub type Response = (
    http::Response<BytesMut>,
    ClientCachePreference,
    ServerCachePreference,
    CompressPreference,
);
pub struct PresentData<'a> {
    _priv: &'a (),
}

pub struct Extensions {
    prime: Vec<&'static dyn Fn(&Uri) -> Option<Uri>>,
    pre: HashMap<
        String,
        &'static dyn Fn(&mut Request<&mut dyn AsyncRead>, FsCache) -> Option<Response>,
    >,
    prepare_single:
        HashMap<String, &'static dyn Fn(&Request<&mut dyn AsyncRead>, FsCache) -> Response>,
    prepare_dir: Vec<(
        String,
        &'static dyn Fn(&Request<&mut dyn AsyncRead>, FsCache) -> Response,
    )>,
    present_internal: HashMap<String, &'static dyn Fn(PresentData<'_>)>,
    present_file: HashMap<String, &'static dyn Fn(PresentData<'_>)>,
    package: Vec<&'static dyn Fn(&mut http::Response<BytesMut>)>,
    post: Vec<&'static dyn Fn(&Bytes, &mut application::ResponsePipe<&mut dyn AsyncWrite>)>,
}
