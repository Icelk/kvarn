use crate::*;

pub fn php(
    mut req: RequestWrapperMut,
    host: HostWrapper,
    path: PathWrapper,
    address: SocketAddr,
) -> RetFut<FatResponse> {
    box_fut!({
        let req = unsafe { req.get_inner() };
        let host = unsafe { host.get_inner() };
        let path = unsafe { path.get_inner() };

        if !path.exists() {
            return utility::default_error_response(StatusCode::NOT_FOUND, host, None).await;
        }

        let body = match req.body_mut().read_to_bytes().await {
            Ok(body) => body,
            Err(_) => {
                return FatResponse::cache(
                    utility::default_error(
                        StatusCode::BAD_REQUEST,
                        Some(host),
                        Some("failed to read body".as_bytes()),
                    )
                    .await,
                )
            }
        };
        let output = match fastcgi::from_prepare(req, &body, path, address, 6633).await {
            Ok(vec) => vec,
            Err(err) => {
                error!("FastCGI failed. {}", err);
                return utility::default_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    host,
                    None,
                )
                .await;
            }
        };
        let output = Bytes::copy_from_slice(&output);
        match kvarn::parse::response_php(&output) {
            Ok(response) => FatResponse::cache(response),
            Err(err) => {
                error!("failed to parse response; {}", err.as_str());
                utility::default_error_response(StatusCode::NOT_FOUND, host, None).await
            }
        }
    })
}
