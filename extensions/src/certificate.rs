use std::io::Cursor;

use kvarn::prelude::*;
use rcgen::{Certificate, CertificateParams, DistinguishedName};
use rustls::pki_types::PrivateKeyDer;
use small_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt,
    NewAccount, NewOrder, OrderStatus,
};
use x509_parser::prelude::FromDer;

static NOT_PUBLIC_ERROR: &str = "we aren't public-facing";

/// Attach automatic certificate generation to a host.
/// `set_host_cert` is a callback, since we can't move `host` into a `'static` context, so you have
/// to provide some method of calling [`Host::live_set_certificate`] on `host` (e.g. by saving a
/// `Arc<host::Collection>` and getting the host from that).
///
/// `new_cert_immediately` should only be used when testing, since this extension reads the current
/// cert and only updates it as needed.
#[allow(clippy::too_many_arguments)]
pub async fn mount<'a, F: Future + Send + 'a>(
    mut set_host_cert: impl FnMut(rustls::sign::CertifiedKey) -> F + Send + Sync + 'static,
    host: &Host,
    extensions: &mut Extensions,
    new_cert_immediately: bool,
    contact: impl IntoIterator<Item = String>,
    account_path: impl AsRef<Path>,
    cert_path: impl AsRef<Path>,
    pk_path: impl AsRef<Path>,
    dev: bool,
) {
    let contact: Vec<_> = contact.into_iter().collect();
    let domain = host.name.clone();
    let alt_names = host.alternative_names.clone();
    let account_path = account_path.as_ref().to_owned();
    let cert_path = cert_path.as_ref().to_owned();
    let pk_path = pk_path.as_ref().to_owned();

    let mut exp = if new_cert_immediately {
        chrono::OffsetDateTime::now_utc()
    } else {
        let cert = host.certificate.read().unwrap();
        cert.as_ref()
            .and_then(|cert| {
                get_expiration(cert.end_entity_cert().unwrap()).map(|(time, self_signed)| {
                    // if self-signed, try to get proper
                    if self_signed && !dev {
                        info!("Detected self-signed cert on {domain}. Trying to get real certificate.");
                        chrono::OffsetDateTime::now_utc()
                    } else {
                        // update cert every 60 days (Let's encrypt gives us 90 days; 90-60 = 30)
                        time - chrono::time::Duration::days(30)
                    }
                })
            })
            .unwrap_or_else(chrono::OffsetDateTime::now_utc)
    };
    info!("Sleep until {exp} before renewing cert on {domain}");

    let mut account = tokio::fs::read_to_string(&account_path)
        .await
        .ok()
        .map(AcmeAccount);

    let tokens = Arc::new(std::sync::RwLock::new(HashMap::with_capacity(4)));

    // extension which watches /.well-known/acme-challenges/<token> (gotten from hashmap)
    let t1 = tokens.clone();
    let t2 = tokens.clone();
    extensions.add_prepare_fn(
        Box::new(move |req: &FatRequest, _host| {
            req.uri()
                .path()
                .strip_prefix("/.well-known/acme-challenge/")
                .map_or(false, |token| {
                    let tokens = t1.read().unwrap();
                    tokens.contains_key(token)
                })
        }),
        prepare!(req, host, _, _, move |t2: Arc<
            std::sync::RwLock<HashMap<String, String>>,
        >| {
            let token = req
                .uri()
                .path()
                .strip_prefix("/.well-known/acme-challenge/")
                .expect("we just checked if this was true");
            let d = {
                let tokens = t2.read().unwrap();
                tokens.get(token).cloned()
            };
            info!("Serving token on `/.well-known/acme-challenge/{token}`: {d:?}");
            let data = if let Some(d) = d {
                d.into_bytes()
            } else {
                return default_error_response(
                    StatusCode::NOT_FOUND,
                    host,
                    Some("challenge is old"),
                )
                .await;
            };
            FatResponse::no_cache(Response::new(Bytes::from(data)))
        }),
        // we need to be higher priority than HTTP -> HTTPS!
        Id::new(
            2_314_867,
            "serve ACME challenges for automatic certificate management",
        ),
    );

    tokio::spawn(async move {
        let mut account_failures = 0;
        loop {
            let left = (exp - chrono::OffsetDateTime::now_utc()).max(chrono::time::Duration::ZERO);
            tokio::time::sleep(left.try_into().expect("we made sure it's positive")).await;
            let duration =
                Duration::from_secs_f32(rand::Rng::gen_range(&mut rand::thread_rng(), 0.0..10.0));
            // so if multiple are dispatched simultaneously, the first one gets the chance to get
            // and write the account
            tokio::time::sleep(duration).await;

            let tokens = tokens.clone();
            let mut acc = account.take();
            if acc.is_none() {
                acc = tokio::fs::read_to_string(&account_path)
                    .await
                    .ok()
                    .map(AcmeAccount);
            }
            let contact = contact.clone();
            let moved_domain = domain.clone();
            let alt_names = alt_names.clone();

            let new_account = tokio::task::spawn_blocking(move || {
                let contact: Vec<_> = contact.iter().map(String::as_str).collect();
                match get_account(&contact, acc.as_ref()) {
                    Ok(acc) => Some(acc),
                    Err(err) => {
                        error!("Failed to get ACME account from Let's Encrypt: {err}");
                        None
                    }
                }
            })
            .await
            .unwrap();
            let Some((new_account, credentials)) = new_account else {
                tokio::time::sleep(Duration::from_secs(60)).await;
                continue;
            };

            let new_account_serialized = AcmeAccount(ron::to_string(&credentials).unwrap());
            if let Err(err) =
                tokio::fs::create_dir_all(&account_path.parent().unwrap_or_else(|| Path::new("/")))
                    .await
            {
                warn!("Failed to write ACME account credentials to {account_path:?}: {err}");
            }
            if let Err(err) =
                tokio::fs::write(&account_path, new_account_serialized.0.as_bytes()).await
            {
                warn!("Failed to write ACME account credentials to {account_path:?}: {err}");
            }
            account = Some(new_account_serialized);

            let d = tokio::task::spawn_blocking(move || {
                get_cert(
                    &new_account,
                    moved_domain,
                    alt_names,
                    |token, data| {
                        let mut tokens = tokens.write().unwrap();
                        tokens.insert(token.to_owned(), data.to_owned());
                    },
                    dev,
                )
            })
            .await
            .unwrap();

            let (new_key, expiration, certs_pem, pk_pem, self_signed) = match d {
                Ok((new_key, expiration, (certs_pem, pk_pem))) => {
                    (new_key, expiration, certs_pem, pk_pem, false)
                }
                Err(small_acme::Error::Str(s)) if s == NOT_PUBLIC_ERROR => {
                    debug!("We're not public facing: don't renew certs");
                    let (og_key, key) = match generate_self_signed_cert(domain.clone()) {
                        Ok(v) => v,
                        Err(err) => {
                            error!("Failed to create self-signed cert: {err}");
                            return;
                        }
                    };
                    info!(
                        "Using self-signed for {domain}. \
                        Consider creating your own self-signed certificate \
                        for persistent browser warnings."
                    );
                    (
                        key,
                        chrono::OffsetDateTime::now_utc()
                            + chrono::time::Duration::days(365 * 2000),
                        og_key.serialize_pem().unwrap(),
                        og_key.serialize_private_key_pem(),
                        true,
                    )
                }
                Err(err) => {
                    if account_failures < 10 {
                        if let small_acme::Error::Http(err) = &err {
                            if let small_acme::ureq::Error::Status(400, _) = &**err {
                                // retry with new account
                                account = None;
                                if tokio::fs::remove_file(&account_path).await.is_err() {
                                    error!("Failed to retry Let's Encrypt with new account");
                                    tokio::time::sleep(Duration::from_secs(60)).await;
                                }
                                account_failures += 1;
                                continue;
                            }
                        }
                    }
                    error!("Failed to renew / acquire TLS certificate: {err}");
                    // retry in 60 minutes
                    tokio::time::sleep(Duration::from_secs(60 * 60)).await;
                    continue;
                }
            };
            account_failures = 0;
            set_host_cert(new_key).await;

            if self_signed {
                exp = chrono::OffsetDateTime::now_utc() + chrono::time::Duration::days(7);
                info!("Sleep until {exp} before retrying proper, not self-signed, certificate on {domain}");
            } else {
                // update cert every 60 days (Let's encrypt gives us 90 days)
                exp = expiration - chrono::time::Duration::days(30);
                info!("Sleep until {exp} before renewing cert (which expires at {expiration}) on {domain})");
            }

            if !certs_pem.is_empty() && !pk_pem.is_empty() && (!self_signed || dev) {
                if let Err(err) =
                    tokio::fs::create_dir_all(&cert_path.parent().unwrap_or_else(|| Path::new("/")))
                        .await
                {
                    error!("Failed to write new TLS certificate (chain): {err}");
                }
                if let Err(err) = tokio::fs::write(&cert_path, certs_pem).await {
                    error!("Failed to write new TLS certificate (chain): {err}");
                }
                if let Err(err) =
                    tokio::fs::create_dir_all(&pk_path.parent().unwrap_or_else(|| Path::new("/")))
                        .await
                {
                    error!("Failed to write new TLS private key: {err}");
                }
                if let Err(err) = tokio::fs::write(&pk_path, pk_pem).await {
                    error!("Failed to write new TLS private key: {err}");
                }
            }
        }
    });
}

pub struct AcmeAccount(pub String);

pub fn get_account(
    contact: &[&str],
    account: Option<&AcmeAccount>,
) -> Result<(Account, AccountCredentials), small_acme::Error> {
    let credentials: Option<AccountCredentials> = account.and_then(|a| {
        ron::from_str(&a.0)
            .map_err(|err| {
                warn!("ACME credentials have an invalid format");
                err
            })
            .ok()
    });
    let account = credentials
        .as_ref()
        .and_then(|c| Account::from_credentials(c.clone()).ok());
    account.zip(credentials).map(Ok).unwrap_or_else(|| {
        Account::create(
            &NewAccount {
                contact,
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            LetsEncrypt::Production.url(),
            None,
        )
    })
}
/// Blocking!
/// `set_token`: (token, data)
/// In return: `(String, String)`: (certs_pem, pk_pem)
pub fn get_cert(
    account: &Account,
    domain: impl Into<String>,
    alt_names: Vec<impl Into<String>>,
    set_token: impl Fn(&str, &str),
    dev: bool,
) -> Result<
    (
        rustls::sign::CertifiedKey,
        chrono::OffsetDateTime,
        (String, String),
    ),
    small_acme::Error,
> {
    let domain = domain.into();
    info!("Get cert for {domain}");

    let identifiers: Vec<_> = std::iter::once(Identifier::Dns(domain.clone()))
        .chain(alt_names.into_iter().map(|v| v.into()).map(Identifier::Dns))
        .collect();
    let mut order = account.new_order(&NewOrder {
        identifiers: &identifiers,
    })?;

    debug!("order state: {:#?}", order.state());

    // Pick the desired challenge type and prepare the response.

    let authorizations = order.authorizations()?;
    let mut challenges = Vec::with_capacity(authorizations.len());
    for auth in &authorizations {
        match auth.status {
            AuthorizationStatus::Pending => {}
            AuthorizationStatus::Valid => continue,
            _ => return Err("unexpected authorization status!".into()),
        }

        let challenge = auth
            .challenges
            .iter()
            .find(|c| c.r#type == ChallengeType::Http01)
            .ok_or("no http01 challenge found")?;

        let Identifier::Dns(identifier) = &auth.identifier;

        set_token(
            &challenge.token,
            order.key_authorization(challenge).as_str(),
        );

        challenges.push((identifier, challenge));
    }

    // Let the server know we're ready to accept the challenges.

    for (_, challenge) in &challenges {
        let mut tries = 0;
        loop {
            let url = format!(
                "http://{domain}/.well-known/acme-challenge/{}",
                challenge.token
            );
            if small_acme::ureq::get(&url).call().is_ok() {
                break;
            }
            tries += 1;
            if tries > 10 {
                if !dev {
                    warn!("Tried 10 times to access {url}, but we don't seem to control that. Using self-signed!");
                }
                return Err(NOT_PUBLIC_ERROR.into());
            }
            std::thread::sleep(Duration::from_millis(1000));
        }
        order.set_challenge_ready(&challenge.url)?;
    }

    // Exponentially back off until the order becomes ready or invalid.

    let mut tries = 1u8;
    let mut delay = Duration::from_millis(250);
    let state = loop {
        std::thread::sleep(delay);
        order.refresh()?;
        let state = order.state();
        if let OrderStatus::Ready | OrderStatus::Invalid | OrderStatus::Valid = state.status {
            debug!("order state: {:#?}", state);
            break state;
        }

        if delay < Duration::from_secs(10) {
            delay *= 2;
        }
        tries += 1;
        if tries < 30 {
            debug!("order is not ready, waiting {delay:?} {state:?} {tries}")
        } else {
            error!("order is not ready {state:?} {tries}");
            return Err(small_acme::Error::Str("order is not ready"));
        }
    };

    if state.status == OrderStatus::Invalid {
        return Err(small_acme::Error::Str("order is invalid"));
    }

    // will only be 1, since we only requested 1 identifier
    let mut names = Vec::with_capacity(challenges.len());
    for (identifier, _) in challenges {
        names.push(identifier.to_owned());
    }

    // If the order is ready, we can provision the certificate.
    // Use the rcgen library to create a Certificate Signing Request.

    let mut params = CertificateParams::new(names.clone());
    params.distinguished_name = DistinguishedName::new();
    let key = Certificate::from_params(params).map_err(|_| "domain names invalid")?;
    let csr = key
        .serialize_request_der()
        .map_err(|_| "let's encrypt gave an invalid cert")?;

    // Finalize the order and print certificate chain, private key and account credentials.

    order.finalize(&csr)?;

    let mut tries = 1u8;
    let mut delay = Duration::from_millis(250);
    let cert_chain_pem = loop {
        std::thread::sleep(delay);
        let cert = order.certificate();
        if let Ok(cert) = cert {
            if let Some(cert) = cert {
                break cert;
            } else {
                return Err(small_acme::Error::Str("empty cert response"));
            }
        }

        if delay < Duration::from_secs(10) {
            delay *= 2;
        }
        tries += 1;
        if tries < 30 {
            debug!("certificate is not ready, waiting {delay:?} tries: {tries}")
        } else {
            error!("certificate is not ready tries: {tries}");
            return Err(small_acme::Error::Str("certificate is not ready"));
        }
    };

    let mut certs = Vec::with_capacity(4);
    for cert in rustls_pemfile::certs(&mut Cursor::new(&cert_chain_pem)) {
        if let Ok(cert) = cert {
            certs.push(cert);
        } else {
            return Err("let's encrypt returned invalid pem certs".into());
        }
    }

    let (expires, _self_signed) =
        get_expiration(&certs[0]).ok_or("let's encrypt gave an invalid pem cert")?;

    Ok((
        rustls::sign::CertifiedKey::new(
            certs,
            rustls::crypto::ring::sign::any_supported_type(&PrivateKeyDer::Pkcs8(
                key.serialize_private_key_der().into(),
            ))
            .map_err(|_| "FATAL: private key is invalid!")?,
        ),
        expires,
        (cert_chain_pem, key.serialize_private_key_pem()),
    ))
}
fn generate_self_signed_cert(
    name: impl Into<String>,
) -> Result<(rcgen::Certificate, rustls::sign::CertifiedKey), Box<dyn std::error::Error>> {
    let key = rcgen::generate_simple_self_signed(vec![name.into()])?;
    let pk = rustls::crypto::ring::sign::any_supported_type(&PrivateKeyDer::Pkcs8(
        key.serialize_private_key_der().into(),
    ))
    .unwrap();
    let cert = vec![key.serialize_der()?.into()];
    Ok((key, rustls::sign::CertifiedKey::new(cert, pk)))
}

fn get_expiration(cert: &[u8]) -> Option<(chrono::OffsetDateTime, bool)> {
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(cert).ok()?;
    let self_signed = cert.issuer().iter_organization().count() == 0
        || cert
            .issuer()
            .iter_common_name()
            .any(|n| n.as_str().map_or(false, |s| s.contains("rcgen")));
    Some((cert.validity().not_after.to_datetime(), self_signed))
}
