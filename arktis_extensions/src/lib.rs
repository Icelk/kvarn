#[allow(unused_imports)]
use arktis::*;

#[cfg(feature = "fastcgi-client")]
pub mod cgi {
    use super::*;
    use fastcgi_client::{Client, Params};
    use std::borrow::Cow;
    use std::io;

    pub enum FCGIError {
        FailedToConnect(io::Error),
        FailedToDoRequest(fastcgi_client::Error),
        NoStdout,
    }
    pub fn connect_to_fcgi(
        port: u16,
        method: &str,
        file_name: &str,
        file_path: &str,
        uri: &str,
        body: &[u8],
    ) -> Result<Vec<u8>, FCGIError> {
        // Create connection to FastCGI server
        let stream = match std::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)) {
            Ok(stream) => stream,
            Err(err) => return Err(FCGIError::FailedToConnect(err)),
        };
        let mut client = Client::new(stream, false);

        let len = body.len().to_string();

        let params = Params::with_predefine()
            .set_request_method(method)
            .set_script_name(file_name)
            .set_script_filename(file_path)
            .set_request_uri(uri)
            .set_document_uri(file_name)
            .set_remote_addr("127.0.0.1")
            .set_remote_port("12345")
            .set_server_addr("127.0.0.1")
            .set_server_port("80")
            .set_server_name(arktis::SERVER_NAME)
            .set_content_type("")
            .set_content_length(len.as_str());

        match client.do_request(&params, &mut (&*body)) {
            Ok(output) => match output.get_stdout() {
                Some(output) => Ok(output),
                None => Err(FCGIError::NoStdout),
            },
            Err(err) => Err(FCGIError::FailedToDoRequest(err)),
        }
    }
    pub fn fcgi_from_data(data: &RequestData) -> Result<Vec<u8>, Cow<'static, str>> {
        let file_name = match parse::format_file_name(data.path) {
            Some(name) => name,
            None => {
                return Err(Cow::Borrowed("Error formatting file name!"));
            }
        };
        let file_path = match parse::format_file_path(data.path) {
            Ok(name) => name,
            Err(_) => {
                return Err(Cow::Borrowed("Getting working directory!"));
            }
        };
        let file_path = match file_path.to_str() {
            Some(path) => path,
            None => {
                return Err(Cow::Borrowed("Error formatting file path!"));
            }
        };

        const PORT: u16 = 6633;

        // Fetch fastcgi server response.
        match connect_to_fcgi(
            6633,
            data.request.method().as_str(),
            file_name,
            file_path,
            data.request.uri().path_and_query().unwrap().as_str(),
            data.request.body(),
        ) {
            Ok(vec) => Ok(vec),
            Err(err) => match err {
                FCGIError::FailedToConnect(err) => Err(Cow::Owned(format!(
                    "Failed to connect to FastCGI server on port {}. IO Err: {}",
                    PORT, err
                ))),
                FCGIError::FailedToDoRequest(err) => Err(Cow::Owned(format!(
                    "Failed to request from FastCGI server! Err: {}",
                    err
                ))),
                FCGIError::NoStdout => Err(Cow::Borrowed("No stdout in response from FastCGI!")),
            },
        }
    }
}
#[allow(dead_code)]
pub mod parse {
    use std::path::{Path, PathBuf};

    pub fn format_file_name<P: AsRef<Path>>(path: &P) -> Option<&str> {
        path.as_ref().file_name().and_then(|os_str| os_str.to_str())
    }
    pub fn format_file_path<P: AsRef<Path>>(path: &P) -> Result<PathBuf, std::io::Error> {
        let mut file_path = std::env::current_dir()?;
        file_path.push(path);
        Ok(file_path)
    }
}

#[cfg(feature = "php")]
pub fn php() -> BoundExtension {
    BoundExtension {
        extension_aliases: &[],
        file_extension_aliases: &["php"],
        ext: Extension::new(&|| {}, &|_, data| {
            // Content type will be HTML!
            // Will be overriden by headers from PHP.
            *data.content_type = ContentType::Html;
            // So it won't remove the query before caching!
            *data.cached = Cached::PerQuery;

            let output = match cgi::fcgi_from_data(&data) {
                Ok(vec) => vec,
                Err(err) => {
                    eprintln!("{}", err);
                    return;
                }
            };
            *data.response = ByteResponse::with_partial_header(output);
        }),
    }
}

pub fn download() -> BoundExtension {
    BoundExtension {
        extension_aliases: &["download"],
        file_extension_aliases: &[],
        ext: Extension::new(&|| {}, &|_, data| {
            *data.content_type = ContentType::Download;
        }),
    }
}
