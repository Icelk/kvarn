use crate::*;
use fastcgi_client::{Client, Params};
use std::borrow::Cow;

pub enum FastcgiError {
    FailedToConnect(io::Error),
    FailedToDoRequest(fastcgi_client::ClientError),
    NoStdout,
}
pub async fn connect(
    _port: u16,
    method: &str,
    file_name: &str,
    file_path: &str,
    uri: &str,
    address: &SocketAddr,
    body: &[u8],
) -> Result<Vec<u8>, FastcgiError> {
    // Create connection to FastCGI server
    #[cfg(windows)]
    let stream = match networking::TcpStream::connect((net::Ipv4Addr::LOCALHOST, _port)).await {
        Ok(stream) => stream,
        Err(err) => return Err(FastcgiError::FailedToConnect(err)),
    };
    #[cfg(unix)]
    let stream = match tokio::net::UnixStream::connect("/run/php-fpm/php-fpm.sock").await {
        Ok(stream) => stream,
        Err(err) => return Err(FastcgiError::FailedToConnect(err)),
    };
    let mut client = Client::new(stream, false);

    let len = body.len().to_string();
    let remote_addr = match address.ip() {
        IpAddr::V4(addr) => addr.to_string(),
        IpAddr::V6(addr) => addr.to_string(),
    };
    let remote_port = address.port().to_string();

    let params = Params::default()
        .set_request_method(method)
        .set_script_name(file_name)
        .set_script_filename(file_path)
        .set_request_uri(uri)
        .set_document_uri(uri)
        .set_remote_addr(&remote_addr)
        .set_remote_port(&remote_port)
        .set_server_addr("0.0.0.0")
        .set_server_port("")
        .set_server_name(kvarn::SERVER)
        .set_content_type("")
        .set_content_length(&len);

    let request = fastcgi_client::Request::new(params, body);

    match client.execute(request).await {
        Ok(output) => match output.get_stdout() {
            Some(output) => Ok(output),
            None => Err(FastcgiError::NoStdout),
        },
        Err(err) => Err(FastcgiError::FailedToDoRequest(err)),
    }
}
pub async fn from_prepare<T>(
    request: &Request<T>,
    body: &[u8],
    path: &Path,
    address: SocketAddr,
    fcgi_server_port: u16,
) -> Result<Vec<u8>, Cow<'static, str>> {
    let file_name = match parse::format_file_name(&path) {
        Some(name) => name,
        None => {
            return Err(Cow::Borrowed("Error formatting file name!"));
        }
    };
    let file_path = match parse::format_file_path(&path) {
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

    // Fetch fastcgi server response.
    match connect(
        fcgi_server_port,
        request.method().as_str(),
        file_name,
        file_path,
        request.uri().path_and_query().unwrap().as_str(),
        &address,
        body,
    )
    .await
    {
        Ok(vec) => Ok(vec),
        Err(err) => match err {
            FastcgiError::FailedToConnect(_err) => {
                #[cfg(windows)]
                {
                    Err(Cow::Owned(format!(
                        "Failed to connect to FastCGI server on port {}. IO Err: {}",
                        fcgi_server_port, _err
                    )))
                }
                #[cfg(unix)]
                {
                    Err(Cow::Borrowed(
                        "Failed to connect to FastCGI on '/run/php-fmp/php-fmp.sock'",
                    ))
                }
            }
            FastcgiError::FailedToDoRequest(err) => Err(Cow::Owned(format!(
                "Failed to request from FastCGI server! Err: {}",
                err
            ))),
            FastcgiError::NoStdout => Err(Cow::Borrowed("No stdout in response from FastCGI!")),
        },
    }
}
