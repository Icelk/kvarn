use crate::*;
use kvarn_fastcgi_client::{Client, Params};
use std::borrow::Cow;

pub enum FastcgiError {
    FailedToConnect(io::Error),
    FailedToDoRequest(kvarn_fastcgi_client::ClientError),
    NoStdout,
}
#[allow(clippy::too_many_arguments)]
pub async fn connect(
    connection: Connection,
    method: &str,
    file_name: &str,
    file_path: &str,
    path: &str,
    query: Option<&str>,
    address: &SocketAddr,
    content_type: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Vec<u8>, FastcgiError> {
    // Create connection to FastCGI server
    let stream = match connection.establish().await {
        Ok(stream) => stream,
        Err(err) => return Err(FastcgiError::FailedToConnect(err)),
    };
    let mut client = Client::new(stream, true);

    let len = body.len().to_string();
    let remote_addr = match address.ip() {
        IpAddr::V4(addr) => addr.to_string(),
        IpAddr::V6(addr) => addr.to_string(),
    };
    let remote_port = address.port().to_string();

    let mut params = Params::default()
        .set_request_method(method)
        .set_script_name(file_name)
        .set_script_filename(file_path)
        .set_request_uri(path)
        .set_document_uri(path)
        .set_remote_addr(&remote_addr)
        .set_remote_port(&remote_port)
        .set_server_addr("0.0.0.0")
        .set_server_port("")
        .set_server_name(kvarn::SERVER)
        .set_content_type("")
        .set_content_length(&len);

    if let Some(query) = query {
        params = params.set_query_string(query);
    }

    let param_headers: Vec<_> = headers
        .iter()
        .filter_map(|(name, value)| {
            if let Ok(value) = value.to_str() {
                let mut name = name.as_str().to_uppercase();
                name.insert_str(0, "HTTP_");
                Some((name, value))
            } else {
                None
            }
        })
        .collect();

    for (name, value) in &param_headers {
        params.insert(name, value);
    }

    let request = kvarn_fastcgi_client::Request::new(params, body);

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
    connection: Connection,
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
        connection,
        request.method().as_str(),
        file_name,
        file_path,
        request.uri().path(),
        request.uri().query(),
        &address,
        request
            .headers()
            .get("content-type")
            .and_then(|header| header.to_str().ok())
            .unwrap_or(""),
        request.headers(),
        body,
    )
    .await
    {
        Ok(vec) => Ok(vec),
        Err(err) => match err {
            FastcgiError::FailedToConnect(err) => Err(Cow::Owned(format!(
                "Failed to connect to FastCGI server on {:?}. IO Err: {}",
                connection, err
            ))),
            FastcgiError::FailedToDoRequest(err) => Err(Cow::Owned(format!(
                "Failed to request from FastCGI server! Err: {}",
                err
            ))),
            FastcgiError::NoStdout => Err(Cow::Borrowed("No stdout in response from FastCGI!")),
        },
    }
}
