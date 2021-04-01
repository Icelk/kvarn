//! # Kvarn extensions
//! A *supporter-lib* for Kvarn to supply extensions to the web server.
//!
//! Use [`mount_all`] to get started quickly.
//!
//! ## An introduction to the *Kvarn extension system*
//! Kvarn extensions can bind to *extension declarations* and to *file extensions*.
//! For example, if you mount the extensions [`download`], it binds the *extension declaration* `download`.
//! If you then, in a file inside your `public/` directory, add `!> download` to the top, the client visiting the url pointing to the file will download it!

use kvarn::{
    comprash::CombinedCachePreference,
    extensions::*,
    prelude::{internals::*, *},
};

/// Mounts all extensions specified in Cargo.toml dependency declaration.
///
/// The current defaults are [`download`], [`cache`], [`php`], and [`templates`]
///
/// They will *always* get included in your server after calling this function.
pub fn mount_all(extensions: &mut Extensions) {
    extensions.add_present_internal("download".to_string(), &download);
    extensions.add_present_internal("cache".to_string(), &cache);
    extensions.add_present_internal("hide".to_string(), &hide);
    extensions.add_present_file("private".to_string(), &hide);
    extensions.add_present_internal("allow-ips".to_string(), &ip_allow);
    #[cfg(feature = "php")]
    extensions.add_present(php);
    #[cfg(feature = "templates")]
    extensions.add_present(templates);
}

#[cfg(feature = "templates")]
pub use templates::templates;

// #[cfg(feature = "fastcgi-client")]
// pub mod cgi {
//     use super::*;
//     use fastcgi_client::{Client, Params};
//     use kvarn::prelude::networking::*;

//     pub enum FCGIError {
//         FailedToConnect(io::Error),
//         FailedToDoRequest(fastcgi_client::Error),
//         NoStdout,
//     }
//     pub fn connect_to_fcgi(
//         port: u16,
//         method: &str,
//         file_name: &str,
//         file_path: &str,
//         uri: &str,
//         address: &SocketAddr,
//         body: &[u8],
//     ) -> Result<Vec<u8>, FCGIError> {
//         // Create connection to FastCGI server
//         let stream = match std::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port)) {
//             Ok(stream) => stream,
//             Err(err) => return Err(FCGIError::FailedToConnect(err)),
//         };
//         let mut client = Client::new(stream, false);

//         let len = body.len().to_string();
//         let remote_addr = match address.ip() {
//             IpAddr::V4(addr) => addr.to_string(),
//             IpAddr::V6(addr) => addr.to_string(),
//         };
//         let remote_port = address.port().to_string();

//         let params = Params::with_predefine()
//             .set_request_method(method)
//             .set_script_name(file_name)
//             .set_script_filename(file_path)
//             .set_request_uri(uri)
//             .set_document_uri(file_name)
//             .set_remote_addr(&remote_addr)
//             .set_remote_port(&remote_port)
//             .set_server_addr("0.0.0.0")
//             .set_server_port("")
//             .set_server_name(kvarn::SERVER_NAME)
//             .set_content_type("")
//             .set_content_length(&len);

//         match client.do_request(&params, &mut (&*body)) {
//             Ok(output) => match output.get_stdout() {
//                 Some(output) => Ok(output),
//                 None => Err(FCGIError::NoStdout),
//             },
//             Err(err) => Err(FCGIError::FailedToDoRequest(err)),
//         }
//     }
//     pub fn fcgi_from_data(data: &PresentData, port: u16) -> Result<Vec<u8>, Cow<'static, str>> {
//         let file_name = match parse::format_file_name(data.path) {
//             Some(name) => name,
//             None => {
//                 return Err(Cow::Borrowed("Error formatting file name!"));
//             }
//         };
//         let file_path = match parse::format_file_path(data.path) {
//             Ok(name) => name,
//             Err(_) => {
//                 return Err(Cow::Borrowed("Getting working directory!"));
//             }
//         };
//         let file_path = match file_path.to_str() {
//             Some(path) => path,
//             None => {
//                 return Err(Cow::Borrowed("Error formatting file path!"));
//             }
//         };

//         // Fetch fastcgi server response.
//         match connect_to_fcgi(
//             port,
//             data.request.method().as_str(),
//             file_name,
//             file_path,
//             data.request.uri().path_and_query().unwrap().as_str(),
//             data.address,
//             data.request.body(),
//         ) {
//             Ok(vec) => Ok(vec),
//             Err(err) => match err {
//                 FCGIError::FailedToConnect(err) => Err(Cow::Owned(format!(
//                     "Failed to connect to FastCGI server on port {}. IO Err: {}",
//                     port, err
//                 ))),
//                 FCGIError::FailedToDoRequest(err) => Err(Cow::Owned(format!(
//                     "Failed to request from FastCGI server! Err: {}",
//                     err
//                 ))),
//                 FCGIError::NoStdout => Err(Cow::Borrowed("No stdout in response from FastCGI!")),
//             },
//         }
//     }
// }
// Ok, since it is used, just not by every extension, and #[CFG] would be too fragile for this.
#[allow(dead_code)]
pub mod parse {
    use super::*;

    pub fn format_file_name<P: AsRef<Path>>(path: &P) -> Option<&str> {
        path.as_ref().file_name().and_then(OsStr::to_str)
    }
    pub fn format_file_path<P: AsRef<Path>>(path: &P) -> Result<PathBuf, io::Error> {
        let mut file_path = std::env::current_dir()?;
        file_path.push(path);
        Ok(file_path)
    }
}

// #[cfg(feature = "php")]
// pub fn php() -> BoundExtension {
//     BoundExtension {
//         extension_aliases: &[],
//         file_extension_aliases: &["php"],
//         ext: Extension::new(&|| {}, &|_, data| {
//             // Content type will be HTML!
//             // Will be overriden by headers from PHP.
//             *data.content_type = Html;
//             // So it won't remove the query before caching!
//             *data.cached = Cached::PerQuery;

//             let output = match cgi::fcgi_from_data(&data, 6633) {
//                 Ok(vec) => vec,
//                 Err(err) => {
//                     eprintln!("{}", err);
//                     return;
//                 }
//             };
//             data.set
//     }
// }

// #[cfg(feature = "templates")]
// pub mod templates {
//     use super::*;

//     pub fn templates() -> BoundExtension {
//         BoundExtension {
//             extension_aliases: &["tmpl"],
//             file_extension_aliases: &[],
//             ext: Extension::new(&|| {}, &|_, data| {
//                 let response = ByteResponse::without_header(handle_template(
//                     &data.args.iter().map(String::as_str).collect::<Vec<_>>(),
//                     data.body,
//                     data.storage,
//                     data.host,
//                 ));

//                 data.set_response(response);
//             }),
//         }
//     }

//     pub fn handle_template(
//         arguments: &[&str],
//         file: &[u8],
//         storage: &mut Storage,
//         host: &Host,
//     ) -> Vec<u8> {
//         // Get templates, from cache or file
//         let templates = read_templates(arguments.iter().skip(1).copied(), storage, host);

//         #[derive(Eq, PartialEq)]
//         enum Stage {
//             Text,
//             Placeholder,
//         };

//         let mut response = Vec::with_capacity(file.len() * 2);

//         let mut stage = Stage::Text;
//         let mut placeholder_start = 0;
//         let mut escaped = 0;
//         for (position, byte) in file.iter().enumerate() {
//             let is_escape = *byte == ESCAPE;

//             match stage {
//                 // If in text stage, check for left bracket. Then set the variables for starting identifying the placeholder for template
//                 // Push the current byte to response, if not start of placeholder
//                 Stage::Text if (escaped == 0 && !is_escape) || escaped == 1 => {
//                     if *byte == L_SQ_BRACKET && escaped != 1 {
//                         placeholder_start = position;
//                         stage = Stage::Placeholder;
//                     } else {
//                         response.push(*byte);
//                     }
//                 }
//                 Stage::Placeholder if escaped != 1 => {
//                     // If placeholder closed
//                     if *byte == R_SQ_BRACKET {
//                         // Check if name is longer than empty
//                         if position.checked_sub(placeholder_start + 2).is_some() {
//                             // Good; we have UTF-8
//                             if let Ok(key) = str::from_utf8(&file[placeholder_start + 1..position])
//                             {
//                                 // If it is a valid template?
//                                 // Frick, we have to own the value for it to be borrow for Arc<String>, no &str here :(
//                                 if let Some(template) = templates.get(&key.to_owned()) {
//                                     // Push template byte-slice to the response
//                                     for byte in &**template {
//                                         response.push(*byte);
//                                     }
//                                 }
//                             }
//                         }
//                         // Set stage to accept new text
//                         stage = Stage::Text;
//                     }
//                 }
//                 // Else, it's a escaping character!
//                 _ => {}
//             }

//             // Do we escape?
//             if is_escape {
//                 escaped += 1;
//                 if escaped == 2 {
//                     escaped = 0;
//                 }
//             } else {
//                 escaped = 0;
//             }
//         }
//         response
//     }
//     fn read_templates<'a, I: DoubleEndedIterator<Item = &'a str>>(
//         files: I,
//         storage: &mut Storage,
//         host: &Host,
//     ) -> HashMap<String, Vec<u8>> {
//         let mut templates = HashMap::with_capacity(32);

//         for template in files.rev() {
//             if let Some(map) = read_templates_from_file(template, storage, host) {
//                 for (key, value) in map.into_iter() {
//                     templates.insert(key, value);
//                 }
//             }
//         }

//         templates
//     }
//     fn read_templates_from_file(
//         template_set: &str,
//         storage: &mut Storage,
//         host: &Host,
//     ) -> Option<HashMap<String, Vec<u8>>> {
//         let mut template_dir = host.path.join("templates");
//         template_dir.push(template_set);

//         // The template file will be access several times.
//         match read_file_cached(&template_dir, storage.get_fs()) {
//             Some(file) => {
//                 let templates = extract_templates(&file[..]);
//                 return Some(templates);
//             }
//             None => None,
//         }
//     }
//     fn extract_templates(file: &[u8]) -> HashMap<String, Vec<u8>> {
//         let mut templates = HashMap::with_capacity(16);

//         let mut last_was_lf = true;
//         let mut escape = false;
//         let mut name_start = 0;
//         let mut name_end = 0usize;
//         let mut newline_size = 1;
//         for (position, byte) in file.iter().enumerate() {
//             // Ignore all CR characters
//             if *byte == CR {
//                 newline_size = 2;
//                 continue;
//             }
//             // Ignore all whitespace
//             if *byte == SPACE || *byte == TAB {
//                 continue;
//             }
//             // If previous char was \, escape!
//             // New template, process previous!
//             if !escape && last_was_lf && *byte == L_SQ_BRACKET {
//                 // If name is longer than empty
//                 if name_end.checked_sub(name_start + 2).is_some() {
//                     // Check if we have a valid UTF-8 string
//                     if let Ok(name) = str::from_utf8(&file[name_start + 1..name_end - 1]) {
//                         // Check if value comes after newline, space, or right after. Then remove the CRLF/space from template value
//                         let add_after_name = if file.get(name_end + newline_size - 1) == Some(&LF) {
//                             newline_size
//                         } else {
//                             if file.get(name_end) == Some(&SPACE) {
//                                 1
//                             } else {
//                                 0
//                             }
//                         };
//                         // Then insert template; name we got from previous step, then bytes from where the previous template definition ended, then our current position, just before the start of the next template
//                         // Returns a byte-slice of the file
//                         templates.insert(
//                             name.to_owned(),
//                             file[name_end + add_after_name..position - newline_size].to_vec(),
//                         );
//                     }
//                 }
//                 // Set start of template name to now
//                 name_start = position;
//             }
//             if *byte == R_SQ_BRACKET {
//                 name_end = position + 1;
//             }

//             last_was_lf = *byte == LF;
//             escape = *byte == ESCAPE;
//         }
//         // Because we add the definitions in the start of the new one, check for last in the end of file
//         if name_end.checked_sub(name_start + 2).is_some() {
//             if let Ok(name) = str::from_utf8(&file[name_start + 1..name_end - 1]) {
//                 // Check if value comes after newline, space, or right after. Then remove the CRLF/space from template value
//                 let add_after_name = if file.get(name_end + newline_size - 1) == Some(&LF) {
//                     newline_size
//                 } else {
//                     if file.get(name_end) == Some(&SPACE) {
//                         1
//                     } else {
//                         0
//                     }
//                 };
//                 templates.insert(
//                     name.to_owned(),
//                     file[name_end + add_after_name..file.len() - newline_size].to_vec(),
//                 );
//             }
//         }
//         templates
//     }
// }

/// Makes the client download the file.
pub fn download(mut data: PresentDataWrapper) -> RetFut<()> {
    Box::pin(async move {
        let data = unsafe { data.get_inner() };
        let headers = data.response_mut().headers_mut();
        kvarn::utility::replace_header_static(headers, "content-type", "application/octet-stream");
    })
}

pub fn cache(mut data: PresentDataWrapper) -> RetFut<()> {
    Box::pin(async move {
        let data = unsafe { data.get_inner() };
        if let Some(preference) = data
            .args()
            .get(1)
            .and_then(|arg| arg.parse::<CombinedCachePreference>().ok())
        {
            *data.server_cache_preference() = preference.0;
            *data.client_cache_preference() = preference.1;
        }
    })
}

pub fn hide(mut data: PresentDataWrapper) -> RetFut<()> {
    Box::pin(async move {
        let data = unsafe { data.get_inner() };
        let error = default_error(http::StatusCode::NOT_FOUND, Some(&data.host().file_cache)).await;
        *data.response_mut() = error;
    })
}

pub fn ip_allow(mut data: PresentDataWrapper) -> RetFut<()> {
    let future = Box::pin(async move {
        let data = unsafe { data.get_inner() };
        let mut matched = false;
        // Loop over denied ip in args
        for denied in data.args().iter() {
            // If parsed
            if let Ok(ip) = denied.parse::<std::net::IpAddr>() {
                // check it against the requests IP.
                if data.address().ip() == ip {
                    matched = true;
                    // Then break out of loop
                    break;
                }
            }
        }
        if !matched {
            // If it does not match, set the response to 404
            let error =
                default_error(http::StatusCode::NOT_FOUND, Some(&data.host().file_cache)).await;
            *data.response_mut() = error;
        }
        *data.server_cache_preference() = kvarn::comprash::ServerCachePreference::None;
        *data.client_cache_preference() = kvarn::comprash::ClientCachePreference::Changing;
    })/*  as Box<(dyn std::future::Future<Output = ()> + Unpin)> */;
    future
}
