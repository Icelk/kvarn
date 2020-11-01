use arktis::*;
#[cfg(feature = "php")]
use fastcgi_client::{Client, Params};

#[cfg(feature = "php")]
pub fn php() -> BoundExtension {
    BoundExtension {
        extension_aliases: &[],
        file_extension_aliases: &["php"],
        ext: Extension::new(&|| {}, &|_, data| {
            // Create connection to FastCGI server
            let stream =
                std::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, 6633)).unwrap();
            let mut client = Client::new(stream, false);

            let file_name = data
                .path
                .file_name()
                .and_then(|os_str| os_str.to_str())
                .unwrap_or("");
            let mut file_path =
                std::env::current_dir().expect("Failed to get current working directory!");
            file_path.push(data.path);
            let file_path = file_path.to_str().unwrap_or("");
            let content_len = format!("{}", data.request.body().len());

            let params = Params::with_predefine()
                .set_request_method(data.request.method().as_str())
                .set_script_name(file_name)
                .set_script_filename(file_path)
                .set_request_uri(data.request.uri().path_and_query().unwrap().as_str())
                .set_document_uri(file_name)
                .set_remote_addr("127.0.0.1")
                .set_remote_port("12345")
                .set_server_addr("127.0.0.1")
                .set_server_port("80")
                .set_server_name(arktis::SERVER_NAME)
                .set_content_type("")
                .set_content_length(&content_len);

            *data.content_type = ContentType::Html;
            // Fetch fastcgi server(php-fpm) response.
            let output = match client.do_request(&params, &mut (&**data.request.body())) {
                Ok(output) => match output.get_stdout() {
                    Some(output) => output,
                    None => {
                        eprintln!("No stdout in response from FastCGI!");
                        if let Some(err) = output
                            .get_stderr()
                            .and_then(|err| String::from_utf8(err).ok())
                        {
                            eprintln!("Stderr: {}", err)
                        }
                        return;
                    }
                },
                Err(err) => {
                    eprintln!("Failed to request from FastCGI server! Err: {}", err);
                    return;
                }
            };

            *data.response = ByteResponse::with_partial_header(output);
        }),
    }
}
