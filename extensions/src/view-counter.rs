use dashmap::{DashMap, DashSet};

use crate::*;

#[derive(Clone)]
pub struct ViewCount {
    articles: Arc<DashMap<String, (bool, u64)>>,
    ips: Arc<DashMap<String, DashSet<IpAddr>>>,
}

async fn parse(s: &str) -> Option<ViewCount> {
    let s = tokio::fs::read_to_string(s).await.ok()?;

    let articles = DashMap::new();
    for l in s.lines().skip(1) {
        // rsplit so the commas in article don't skrew with us
        let (article, count) = l.rsplit_once(',')?;
        let article = if article.contains("\\,")
            || article.contains("\\\\")
            || article.contains("\\\n")
            || article.contains("\\\r")
        {
            article
                .replace("\\\\", "\\")
                .replace("\\,", ",")
                .replace("\\n", "\n")
                .replace("\\r", "\r")
        } else {
            article.to_owned()
        };
        let count = count.parse().ok()?;
        articles.insert(article, (false, count));
    }
    Some(ViewCount {
        articles: Arc::new(articles),
        ips: Arc::new(DashMap::new()),
    })
}

pub async fn mount(
    extensions: &mut Extensions,
    predicate: impl Fn(&FatRequest) -> bool + Send + Sync + 'static,
    log_file_name: impl Into<String>,
    commit_interval: Duration,
    accept_same_ip_interval: Duration,
) -> ViewCount {
    let predicate = Box::new(predicate);
    let path = log_file_name.into();
    let total_path = format!("{path}-totals.csv");
    let changes_path = format!("{path}-history.csv");

    let view_count = match parse(&total_path).await {
        Some(x) => x,
        None => {
            #[cfg(feature = "uring")]
            let path_exists = tokio_uring::fs::statx(&total_path).await.is_ok();
            #[cfg(not(feature = "uring"))]
            let path_exists = tokio::fs::metadata(&total_path).await.is_ok();

            if path_exists {
                warn!("Overriding view count total at '{total_path}'");
            }
            ViewCount {
                articles: Arc::new(DashMap::new()),
                ips: Arc::new(DashMap::new()),
            }
        }
    };

    {
        let c = view_count.clone();
        let _task = spawn(async move {
            loop {
                tokio::time::sleep(commit_interval).await;

                let mut any_changed = false;
                for v in c.articles.iter() {
                    if v.0 {
                        any_changed = true;
                    }
                }
                if any_changed {
                    #[allow(unused_mut)] // uring doesn't mutate
                    let mut file = match fs::OpenOptions::new()
                        .create(true)
                        .write(true)
                        .append(true)
                        .open(&changes_path)
                        .await
                    {
                        Err(err) => {
                            error!(
                            "Failed to open file to log view count history ('{changes_path}'): {err:?}"
                        );
                            break;
                        }
                        Ok(f) => f,
                    };
                    #[cfg(feature = "uring")]
                    let size = tokio_uring::fs::statx(&changes_path)
                        .await
                        .expect("Failed to get stat for view counter changes file").stx_size;
                    #[cfg(not(feature = "uring"))]
                    let size = tokio::fs::metadata(&changes_path)
                        .await
                        .expect("Failed to get stat for view counter changes file").len();


                    let mut data = String::new();

                    if size == 0 {
                        data.push_str("article path,view count,Rfc3339 date\n");
                    }
                    let now = chrono::OffsetDateTime::now_utc()
                        .replace_nanosecond(0)
                        .unwrap();
                    let date = now
                        .format(&chrono::time::format_description::well_known::Rfc3339)
                        .unwrap();
                    for mut v in c.articles.iter_mut() {
                        let (article, (changed, count)) = v.pair_mut();

                        if *changed {
                            *changed = false;
                            let count = *count;
                            let line = if article.contains(',')
                                || article.contains('\\')
                                || article.contains('\n')
                                || article.contains('\r')
                            {
                                let article = article.replace('\\', "\\\\");
                                let article = article.replace(',', "\\,");
                                let article = article.replace('\n', "\\n");
                                let article = article.replace('\r', "\\r");

                                format!("{article},{count},{date}\n")
                            } else {
                                format!("{article},{count},{date}\n")
                            };
                            debug!("Add to history: {:?}", line.trim_end());
                            data.push_str(&line);
                        }
                    }

                    #[cfg(feature = "uring")]
                    file.write_all_at(data.into_bytes(), 0).await.0.unwrap();
                    #[cfg(not(feature = "uring"))]
                    file.write_all(data.as_bytes()).await.unwrap();

                    drop(file);
                    debug!("Updating total");
                    #[allow(unused_mut)] // uring doesn't mutate
                    let mut file = match fs::File::create(&total_path).await {
                        Err(err) => {
                            error!(
                            "Failed to open file to log view count history ('{changes_path}'): {err:?}"
                        );
                            break;
                        }
                        Ok(f) => f,
                    };
                    let mut data = b"article path,view count\n".to_vec();
                    for v in c.articles.iter() {
                        let count = v.1;
                        let article = v.key();
                        let line = if article.contains(',')
                            || article.contains('\\')
                            || article.contains('\n')
                            || article.contains('\r')
                        {
                            let article = article.replace('\\', "\\\\");
                            let article = article.replace(',', "\\,");
                            let article = article.replace('\n', "\\n");
                            let article = article.replace('\r', "\\r");

                            format!("{article},{count}\n")
                        } else {
                            format!("{article},{count}\n")
                        };
                        data.append(&mut line.into_bytes());
                    }
                    #[cfg(feature = "uring")]
                    file.write_all_at(data, 0).await.0.unwrap();
                    #[cfg(not(feature = "uring"))]
                    file.write_all(&data).await.unwrap();
                    drop(file);
                }
            }
        }).await;
    }
    {
        let c = view_count.clone();
        threading::spawn(async move {
            loop {
                tokio::time::sleep(accept_same_ip_interval).await;
                c.ips.clear();
            }
        });
    }

    let c = view_count.clone();
    extensions.add_post(
        post!(
            request,
            _host,
            _response_pipe,
            _identity_body,
            addr,
            move |c: ViewCount,
                  predicate: Box<dyn Fn(&FatRequest) -> bool + Send + Sync + 'static>| {
                let c: &ViewCount = c;
                if !predicate(request)
                    || c.ips
                        .get(request.uri().path())
                        .is_some_and(|ips| ips.contains(&addr.ip()))
                {
                    return;
                }
                let mut ips = None;
                while ips.is_none() {
                    ips = c.ips.get(request.uri().path());
                    if ips.is_none() {
                        c.ips
                            .insert(request.uri().path().to_owned(), DashSet::new());
                    }
                }
                let ips = ips.unwrap();
                ips.insert(addr.ip());
                let mut count = c
                    .articles
                    .entry(request.uri().path().to_string())
                    .or_insert((false, 0));
                count.0 = true;
                count.1 += 1;
            }
        ),
        Id::new(-1024, "View counter").no_override(),
    );
    let c = view_count.clone();
    extensions.add_present_internal(
        "view-counter",
        present!(args, move |c: ViewCount| {
            let needle = b"${view-count}";
            let mut pos = 0;
            let mut view_count = None;
            while let Some(idx) = memchr::memmem::find(&args.response.body()[pos..], needle) {
                let idx = pos + idx;
                pos = idx;
                let view_count = match &view_count {
                    Some(v) => v,
                    None => {
                        let article = args.request.uri().path();
                        let n = c.articles.get(article).map_or(1, |v| v.1);
                        view_count.insert(n.to_string())
                    }
                };
                args.response
                    .body_mut()
                    .replace(idx..idx + needle.len(), view_count.as_bytes());
            }
        }),
    );
    view_count
}
pub fn starts_with_predicate(
    starts_with: impl Into<String>,
) -> impl Fn(&FatRequest) -> bool + Send + Sync + 'static {
    let path = starts_with.into();
    move |request| {
        request.uri().path().ends_with(".html") && request.uri().path().starts_with(&path)
    }
}
