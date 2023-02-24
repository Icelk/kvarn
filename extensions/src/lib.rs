//! # Kvarn extensions
//! A *supporter-lib* for Kvarn to supply extensions to the web server.
//!
//! Use [`new()`] to get started quickly.
//!
//! ## An introduction to the *Kvarn extension system*
//! On of the many things Kvarn extensions can to is bind to *extension declarations* and to *file extensions*.
//! For example, if you mount the extensions [`download`], it binds the *extension declaration* `download`.
//! If you then, in a file inside your `public/` directory, add `!> download` to the top, the client visiting the url pointing to the file will download it.

#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![deny(clippy::all)]

use kvarn::{extensions::*, prelude::*};

#[cfg(feature = "reverse-proxy")]
#[path = "reverse-proxy.rs"]
pub mod reverse_proxy;
#[cfg(feature = "connection")]
pub use connection::Connection;
#[cfg(feature = "reverse-proxy")]
pub use reverse_proxy::{localhost, static_connection, Manager as ReverseProxy};

#[cfg(feature = "push")]
pub mod push;
#[cfg(feature = "push")]
pub use push::{mount as mount_push, SmartPush};

#[cfg(feature = "kvarn-fastcgi-client")]
pub mod fastcgi;

#[cfg(feature = "php")]
pub mod php;
#[cfg(feature = "php")]
pub use php::mount_php as php;

#[cfg(feature = "templates")]
pub mod templates;
#[cfg(feature = "templates")]
pub use templates::templates as templates_ext;

#[cfg(feature = "connection")]
pub mod connection;

#[cfg(feature = "certificate")]
pub mod certificate;

#[path = "view-counter.rs"]
pub mod view_counter;

/// Creates a new `Extensions` and adds all enabled `kvarn_extensions`.
///
/// See [`mount_all()`] for more information.
pub fn new() -> Extensions {
    let mut e = Extensions::new();
    mount_all(&mut e);
    e
}

/// Mounts all extensions specified in Cargo.toml dependency declaration.
/// The extensions listed below will always get included in your server after calling this function.
///
/// The current defaults are:
/// - [`download()`] (present name `download`)
/// - [`cache()`] (present name `cache`)
/// - [`hide()`] (present name `hide` & `private`)
/// - [`ip_allow()`] (present name `allow-ips`)
/// - [`templates_ext()`] if the feature `templates` is enabled (present name `tmpl`)
/// - [`push::mount()`] if the feature `push` is enabled
///
/// > To add PHP, use [`php()`].
///
/// The push extension uses the [default](SmartPush::default) settings.
///
/// # Examples
///
/// ```no_run
/// use kvarn::prelude::*;
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() {
/// let mut extensions = Extensions::new();
/// kvarn_extensions::mount_all(&mut extensions);
///
/// let host = Host::unsecure("localhost", PathBuf::from("web"), Extensions::default(), host::Options::default());
/// let data = HostCollection::builder().insert(host).build();
/// let port_descriptor = PortDescriptor::new(8080, data);
///
/// let shutdown_manager = run_config![port_descriptor].execute().await;
/// shutdown_manager.wait().await;
/// # }
pub fn mount_all(extensions: &mut Extensions) {
    extensions.add_present_internal("download", Box::new(download));
    extensions.add_present_internal("cache", Box::new(cache));
    extensions.add_present_internal("hide", Box::new(hide));
    extensions.add_present_file("private", Box::new(hide));
    extensions.add_present_internal("allow-ips", Box::new(ip_allow));
    #[cfg(feature = "templates")]
    extensions.add_present_internal("tmpl", Box::new(templates_ext));
    #[cfg(feature = "push")]
    push::mount(extensions, SmartPush::default());
}

// Ok, since it is used, just not by every extension, and #[CFG] would be too fragile for this.
#[allow(dead_code)]
pub mod parse {
    use super::*;

    pub fn format_file_name<P: AsRef<Path>>(path: &P) -> Option<&str> {
        path.as_ref().file_name().and_then(std::ffi::OsStr::to_str)
    }
    pub fn format_file_path<P: AsRef<Path>>(path: &P) -> Result<PathBuf, io::Error> {
        let mut file_path = std::env::current_dir()?;
        file_path.push(path);
        Ok(file_path)
    }
}

/// Makes the client download the file.
pub fn download<'a>(data: &'a mut extensions::PresentData<'a>) -> RetFut<'a, ()> {
    let headers = data.response.headers_mut();
    headers.insert(
        "content-type",
        HeaderValue::from_static("application/octet-stream"),
    );
    ready(())
}

pub fn cache<'a>(data: &'a mut extensions::PresentData<'a>) -> RetFut<'a, ()> {
    fn parse<'a, I: Iterator<Item = &'a str>>(
        iter: I,
    ) -> (
        Option<comprash::ClientCachePreference>,
        Option<comprash::ServerCachePreference>,
    ) {
        let mut c = None;
        let mut s = None;
        for arg in iter {
            let mut parts = arg.split(':');
            let domain = parts.next();
            let cache = parts.next();
            if let (Some(domain), Some(cache)) = (domain, cache) {
                match domain {
                    "client" => {
                        if let Ok(preference) = cache.parse() {
                            c = Some(preference)
                        }
                    }
                    "server" => {
                        if let Ok(preference) = cache.parse() {
                            s = Some(preference)
                        }
                    }
                    _ => {}
                }
            }
        }
        (c, s)
    }
    let preference = parse(data.args.iter());
    if let Some(c) = preference.0 {
        *data.client_cache_preference = c;
    }
    if let Some(s) = preference.1 {
        *data.server_cache_preference = s;
    }
    ready(())
}

pub fn hide<'a>(data: &'a mut extensions::PresentData<'a>) -> RetFut<'a, ()> {
    box_fut!({
        #[allow(unused_mut)] // cfg
        let mut error = default_error(StatusCode::NOT_FOUND, Some(data.host), None).await;
        let arguments = utils::extensions::PresentExtensions::new(error.body().clone());
        if let Some(arguments) = &arguments {
            #[allow(unused_variables)] // cfg
            for argument in arguments.iter() {
                #[cfg(feature = "templates")]
                if argument.name() == "tmpl" {
                    let mut error = error.map(|b| {
                        let mut c = utils::BytesCow::from(b);
                        c.replace(0..arguments.data_start(), b"");
                        c
                    });
                    templates::handle_template(&argument, error.body_mut(), data.host).await;
                    *data.response = error;
                    return;
                }
            }
        }

        *data.response = error.map(Into::into);
    })
}

pub fn ip_allow<'a>(data: &'a mut extensions::PresentData<'a>) -> RetFut<'a, ()> {
    box_fut!({
        let mut matched = false;
        // Loop over denied ip in args
        for denied in data.args.iter() {
            // If parsed
            if let Ok(ip) = denied.parse::<IpAddr>() {
                // check it against the requests IP.
                if data.address.ip() == ip {
                    matched = true;
                    // Then break out of loop
                    break;
                }
            }
        }
        *data.server_cache_preference = comprash::ServerCachePreference::None;
        *data.client_cache_preference = comprash::ClientCachePreference::Changing;

        if !matched {
            // If it does not match, set the response to 404
            let error = default_error(StatusCode::NOT_FOUND, Some(data.host), None).await;
            *data.response = error.map(Into::into);
        }
    })
}

/// Forces the responses matching `rules` to be cached according to their respective preference.
/// Useful when you have compiled away cache, but still want images and fonts to be cached.
///
/// Rules can take three shapes.
/// 1. Matching all file extensions. Here, the rule str have to start with a `.`
/// 2. Path start with. Matches all responses which start with the rule. str has to start with `/`
/// 3. Path contains rule. For example, `*target*` matches `/target/bin/kvarn`,
///    `/a/really/long/path/with/some_target_name/in/it`, but not `/tar/get` or
///    `/articles/rust_Target`.
///
/// The priority for the [`Package`] extension is `16`
pub type ForceCacheRules = Vec<(String, comprash::ClientCachePreference)>;
pub fn force_cache(extensions: &mut Extensions, rules: ForceCacheRules) {
    extensions.add_package(
        package!(response, req, _, _, move |rules: ForceCacheRules| {
            let extension = req.uri().path().split('.').last();
            let path = req.uri().path();
            if let Some(extension) = extension {
                for (rule, preference) in rules {
                    let replace = (rule.starts_with('/') && path.starts_with(rule))
                        || rule.strip_prefix('.').map_or(false, |ext| ext == extension)
                        || rule
                            .strip_prefix('*')
                            .and_then(|rule| rule.strip_suffix('*'))
                            .map_or(false, |rule| path.contains(rule));
                    if replace {
                        if let Some(h) = preference.as_header() {
                            response.headers_mut().insert("cache-control", h);
                        }
                    }
                }
            }
        }),
        extensions::Id::new(16, "force_cache: Adding cache-control header").no_override(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn all() {
        let extensions = new();
        let _server = kvarn_testing::ServerBuilder::from(extensions).run().await;
    }
}
