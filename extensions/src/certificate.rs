use std::io::Cursor;

use kvarn::prelude::*;
use rcgen::{Certificate, CertificateParams, DistinguishedName};
use small_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt,
    NewAccount, NewOrder, OrderStatus,
};
use x509_parser::prelude::FromDer;

/// `save_cert_pk`: Fn(certs, private_key)
#[allow(clippy::too_many_arguments)]
pub async fn mount<'a, F: Future + Send + 'a>(
    mut set_host_cert: impl FnMut(rustls::sign::CertifiedKey) -> F + Send + Sync + 'static,
    host: &Host,
    extensions: &mut Extensions,
    new_cert_immedately: bool,
    contact: impl IntoIterator<Item = String>,
    account_path: impl AsRef<Path>,
    cert_path: impl AsRef<Path>,
    pk_path: impl AsRef<Path>,
) {
    let contact: Vec<_> = contact.into_iter().collect();
    let domain = host.name.clone();
    let alt_names = host.alternative_names.clone();
    let account_path = account_path.as_ref().to_owned();
    let cert_path = cert_path.as_ref().to_owned();
    let pk_path = pk_path.as_ref().to_owned();

    let mut exp = if new_cert_immedately {
        chrono::OffsetDateTime::now_utc()
    } else {
        let cert = host.certificate.read().unwrap();
        cert.as_ref()
            .and_then(|cert| {
                get_expiration(&cert.end_entity_cert().unwrap().0)
                    // update cert every 60 days (Let's encrypt gives us 90 days)
                    .map(|time| time - chrono::time::Duration::days(30))
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
            let Some(new_account) = new_account else {
                tokio::time::sleep(Duration::from_secs(60)).await;
                continue;
            };

            let new_account_serialized =
                AcmeAccount(ron::to_string(&new_account.credentials()).unwrap());
            if let Err(err) =
                tokio::fs::write(&account_path, new_account_serialized.0.as_bytes()).await
            {
                warn!("Failed to write ACME account credentials to {account_path:?}: {err}");
            }
            account = Some(new_account_serialized);

            let d = tokio::task::spawn_blocking(move || {
                match get_cert(&new_account, &moved_domain, alt_names, |token, data| {
                    let mut tokens = tokens.write().unwrap();
                    tokens.insert(token.to_owned(), data.to_owned());
                }) {
                    Ok(d) => Some(d),
                    Err(err) => {
                        error!("Failed to renew / acquire TLS certificate: {err}");
                        None
                    }
                }
            })
            .await
            .unwrap();

            let Some((new_key, expiration, (certs_pem, pk_pem))) = d else {
                tokio::time::sleep(Duration::from_secs(60)).await;
                continue;
            };
            set_host_cert(new_key).await;
            // update cert every 60 days (Let's encrypt gives us 90 days)
            exp = expiration - chrono::time::Duration::days(30);
            info!("Sleep until {exp} before renewing cert (which expires at {expiration}) on {domain}");

            if let Err(err) = tokio::fs::write(&cert_path, certs_pem).await {
                error!("Failed to write new TLS certificate (chain): {err}");
            }
            if let Err(err) = tokio::fs::write(&pk_path, pk_pem).await {
                error!("Failed to write new TLS private key: {err}");
            }
        }
    });
}

pub struct AcmeAccount(pub String);

pub fn get_account(
    contact: &[&str],
    account: Option<&AcmeAccount>,
) -> Result<Account, small_acme::Error> {
    let credentials: Option<AccountCredentials> = account.and_then(|a| {
        ron::from_str(&a.0)
            .map_err(|err| {
                warn!("ACME credentials have an invalid format");
                err
            })
            .ok()
    });
    let account = credentials.and_then(|c| Account::from_credentials(c).ok());
    account.map(Ok).unwrap_or_else(|| {
        Account::create(
            &NewAccount {
                contact,
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            LetsEncrypt::Production.url(),
        )
    })
}
/// Blocking!
/// `set_token`: (token, data)
/// In return: `(String, String)`: (certs_pem, pk_pem)
pub fn get_cert(
    account: &Account,
    domain: impl Into<String>,
    alt_names: Vec<String>,
    set_token: impl Fn(&str, &str),
) -> Result<
    (
        rustls::sign::CertifiedKey,
        chrono::OffsetDateTime,
        (String, String),
    ),
    small_acme::Error,
> {
    // Create the ACME order based on the given domain names.
    // Note that this only needs an `&Account`, so the library will let you
    // process multiple orders in parallel for a single account.

    let identifiers: Vec<_> = std::iter::once(Identifier::Dns(domain.into()))
        .chain(alt_names.iter().cloned().map(Identifier::Dns))
        .collect();
    let (mut order, state) = account.new_order(&NewOrder {
        identifiers: &identifiers,
    })?;

    info!("order state: {:#?}", state);
    // assert!(matches!(state.status, OrderStatus::Pending));

    // Pick the desired challenge type and prepare the response.

    let authorizations = order.authorizations(&state.authorizations)?;
    let mut challenges = Vec::with_capacity(authorizations.len());
    for authz in &authorizations {
        match authz.status {
            AuthorizationStatus::Pending => {}
            AuthorizationStatus::Valid => continue,
            _ => return Err("unexpected authorization status!".into()),
        }

        let challenge = authz
            .challenges
            .iter()
            .find(|c| c.r#type == ChallengeType::Http01)
            .ok_or("no http01 challenge found")?;

        let Identifier::Dns(identifier) = &authz.identifier;

        set_token(
            &challenge.token,
            order.key_authorization(challenge).as_str(),
        );

        challenges.push((identifier, &challenge.url));
    }

    // Let the server know we're ready to accept the challenges.

    for (_, url) in &challenges {
        order.set_challenge_ready(url)?;
    }

    // Exponentially back off until the order becomes ready or invalid.

    let mut tries = 1u8;
    let mut delay = Duration::from_millis(250);
    let state = loop {
        std::thread::sleep(delay);
        let state = order.state()?;
        if let OrderStatus::Ready | OrderStatus::Invalid = state.status {
            info!("order state: {:#?}", state);
            break state;
        }

        delay *= 2;
        tries += 1;
        match tries < 5 {
            true => info!("order is not ready, waiting {delay:?} {state:?} {tries}"),
            false => {
                error!("order is not ready {state:?} {tries}");
                return Err(small_acme::Error::Str("order is not ready"));
            }
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

    let cert_chain_pem = order.finalize(&csr, &state.finalize)?;

    let certs = rustls_pemfile::certs(&mut Cursor::new(&cert_chain_pem))
        .map_err(|_| "let's encrypt returned invalid pem certs")?;

    let expires = get_expiration(&certs[0]).ok_or("let's encrypt gave an invalid pem cert")?;

    Ok((
        rustls::sign::CertifiedKey::new(
            certs.into_iter().map(rustls::Certificate).collect(),
            rustls::sign::any_supported_type(&rustls::PrivateKey(key.serialize_private_key_der()))
                .map_err(|_| "FATAL: private key is invalid!")?,
        ),
        expires,
        (cert_chain_pem, key.serialize_private_key_pem()),
    ))
}

fn get_expiration(cert: &[u8]) -> Option<chrono::OffsetDateTime> {
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(cert).ok()?;
    Some(cert.validity().not_after.to_datetime())
}
