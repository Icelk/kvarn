use std::collections::{HashMap, HashSet};

use crate::*;

#[derive(Clone)]
pub struct ViewCount {
    articles: Arc<Mutex<HashMap<String, (bool, u64)>>>,
    ips: Arc<RwLock<HashMap<String, HashSet<IpAddr>>>>,
}

async fn parse(s: &str) -> Option<ViewCount> {
    let s = tokio::fs::read_to_string(s).await.ok()?;

    let mut articles = HashMap::new();
    for l in s.lines().skip(1) {
        // rsplit so the commas in article don't skrew with us
        let (article, count) = l.rsplit_once(',')?;
        let article = if article.contains("\\,")
            || article.contains("\\\\")
            || article.contains("\\\n")
            || article.contains("\\\r")
        {
            article
                .replace("\\,", ",")
                .replace("\\\\", "\\")
                .replace("\\n", "\n")
                .replace("\\r", "\r")
        } else {
            article.to_owned()
        };
        let count = count.parse().ok()?;
        articles.insert(article, (false, count));
    }
    Some(ViewCount {
        articles: Arc::new(Mutex::new(articles)),
        ips: Arc::new(RwLock::new(HashMap::new())),
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

    let view_count = parse(&total_path).await.unwrap_or_else(|| {
        warn!("Overriding view count total at '{total_path}'");
        ViewCount {
            articles: Arc::new(Mutex::new(HashMap::new())),
            ips: Arc::new(RwLock::new(HashMap::new())),
        }
    });

    {
        let c = view_count.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(commit_interval).await;

                let mut lock = c.articles.lock().await;
                let mut any_changed = false;
                for (_, (changed, _)) in lock.iter() {
                    if *changed {
                        any_changed = true;
                    }
                }
                if any_changed {
                    let mut file = match tokio::fs::OpenOptions::new()
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
                    if file.metadata().await.unwrap().len() == 0 {
                        file.write_all(b"article path,view count,Rfc3339 date\n")
                            .await
                            .unwrap();
                    }
                    let now = chrono::OffsetDateTime::now_utc()
                        .replace_nanosecond(0)
                        .unwrap();
                    let date = now
                        .format(&chrono::time::format_description::well_known::Rfc3339)
                        .unwrap();
                    for (article, (changed, count)) in lock.iter_mut() {
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
                            info!("Add to history: {:?}", line.trim_end());
                            file.write_all(line.as_bytes()).await.unwrap();
                        }
                    }
                    file.flush().await.unwrap();
                    drop(file);
                    info!("Updating total");
                    let mut file = match tokio::fs::File::create(&total_path).await {
                        Err(err) => {
                            error!(
                            "Failed to open file to log view count history ('{changes_path}'): {err:?}"
                        );
                            break;
                        }
                        Ok(f) => f,
                    };
                    file.write_all(b"article path,view count\n").await.unwrap();
                    for (article, (_, count)) in lock.iter() {
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
                        file.write_all(line.as_bytes()).await.unwrap();
                    }
                    file.flush().await.unwrap();
                    drop(file);
                }
            }
        });
    }
    {
        let c = view_count.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(accept_same_ip_interval).await;
                c.ips.write().await.clear();
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
                        .read()
                        .await
                        .get(request.uri().path())
                        .map_or(false, |ips| ips.contains(&addr.ip()))
                {
                    return;
                }
                let mut ips_articles = c.ips.write().await;
                let ips = ips_articles
                    .entry(request.uri().path().to_string())
                    .or_default();
                ips.insert(addr.ip());
                let mut l = c.articles.lock().await;
                let mut count = l
                    .entry(request.uri().path().to_string())
                    .or_insert((false, 0));
                count.0 = true;
                count.1 += 1;
            }
        ),
        Id::new(-32, "HTTP/2 push"),
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
