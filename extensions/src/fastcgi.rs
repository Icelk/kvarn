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
    let client = Client::new(stream);

    let remote_addr = match address.ip() {
        IpAddr::V4(addr) => addr.to_string(),
        IpAddr::V6(addr) => addr.to_string(),
    };
    let mut params = Params::default()
        .request_method(method)
        .script_name(file_name)
        .script_filename(file_path)
        .request_uri(path)
        .document_uri(path)
        .remote_addr(&remote_addr)
        .remote_port(address.port())
        .server_addr("0.0.0.0")
        .server_name(extensions::SERVER_NAME_VERSION)
        .content_type(content_type)
        .content_length(body.len());

    if let Some(query) = query {
        params = params.query_string(query);
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
        params.insert(Cow::Borrowed(name), Cow::Borrowed(value));
    }

    let request = kvarn_fastcgi_client::Request::new(params, body);

    match client.execute_once(request).await {
        Ok(output) => match output.stdout {
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
        connection.clone(),
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
                "Failed to connect to FastCGI server on {connection:?}. IO Err: {err}",
            ))),
            FastcgiError::FailedToDoRequest(err) => Err(Cow::Owned(format!(
                "Failed to request from FastCGI server! Err: {err}",
            ))),
            FastcgiError::NoStdout => Err(Cow::Borrowed("No stdout in response from FastCGI!")),
        },
    }
}
