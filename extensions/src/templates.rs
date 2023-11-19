use crate::*;

type TemplateMap = HashMap<CompactString, Bytes>;
pub struct Cache(comprash::MokaCache<CompactString, (chrono::OffsetDateTime, Arc<TemplateMap>)>);
impl Cache {
    pub fn new() -> Arc<Self> {
        Arc::new(Self(comprash::MokaCache::default()))
    }
    async fn resolve_template(
        &self,
        host: &Host,
        template: &str,
        files: &[impl AsRef<str>],
    ) -> Option<Bytes> {
        for file in files {
            let tmpls = self.get_file(host, file.as_ref()).await;
            if let Some(tmpls) = tmpls {
                if let Some(tmpl) = tmpls.get(template) {
                    return Some(tmpl.clone());
                }
            }
        }
        None
    }
    async fn get_file(&self, host: &Host, path: &str) -> Option<Arc<TemplateMap>> {
        if let Some(tmpls) = self.0.cache.get(path) {
            let mtime = host
                .file_cache
                .as_ref()
                .and_then(|cache| cache.cache.get(path));
            let mtime = match mtime {
                Some(opt) => opt?.0,
                None => {
                    let stat = read::stat(path).await;
                    if let Some(stat) = stat {
                        stat.mtime
                    } else {
                        if let Some(c) = &host.file_cache {
                            c.cache.insert(path.to_compact_string(), None);
                        }
                        return None;
                    }
                }
            };
            if mtime <= tmpls.0 {
                return Some(tmpls.1);
            }
        }
        let (file, mtime) = read::file_cached_with_mtime(path, host.file_cache.as_ref()).await?;
        let map = Arc::new(extract_templates(file));
        self.0.cache.insert(path.to_compact_string(), (mtime, map));
        self.0.cache.get(path).map(|(_, map)| map)
    }
}

#[derive(Eq, PartialEq)]
enum Stage {
    Text,
    Placeholder,
}

pub fn templates(cache: Arc<Cache>) -> Box<dyn PresentCall> {
    present!(data, move |cache: Arc<Cache>| {
        handle_template(cache, &data.args, data.response.body_mut(), data.host).await;
    })
}

pub async fn handle_template(
    cache: &Cache,
    arguments: &utils::PresentArguments,
    body: &mut utils::BytesCow,
    host: &Host,
) {
    let files: Vec<_> = arguments.iter().rev().map(|s| path(host, s)).collect();

    // Remove first line if it contains "tmpl-ignore", for formatting quirks.
    let mut file = body.as_ref();
    {
        let limit = 48;
        let first_line_end = file
            .iter()
            .copied()
            .enumerate()
            .position(|(pos, byte)| pos >= limit || byte == LF);

        if first_line_end.unwrap_or(0) != limit {
            if let Some(first_line_end) = first_line_end {
                if let Ok(first_line) = str::from_utf8(&file[..=first_line_end]) {
                    if first_line.contains("tmpl-ignore") {
                        file = &file[first_line_end + 1..];
                    }
                }
            }
        }
    }

    let mut response = BytesMut::with_capacity(file.len() * 3 / 2);

    let mut stage = Stage::Text;
    let mut placeholder_start = 0;
    let mut escaped = 0;
    let mut start_byte = Some(0);

    for (position, byte) in file.iter().copied().enumerate() {
        let is_escape = byte == b'\\';

        match stage {
            Stage::Text => {
                if file[position..].starts_with(b"$[") {
                    let previous = &file[position.saturating_sub(2)..position];
                    let a = if previous.len() == 1 {
                        None
                    } else {
                        previous.first().copied()
                    };
                    let b = previous.last().copied();
                    match (a, b) {
                        (Some(b'\\'), Some(b'\\')) => {
                            response
                                .extend_from_slice(&file[start_byte.take().unwrap()..position - 1]);
                            placeholder_start = position;
                            stage = Stage::Placeholder;
                        }
                        (_, Some(b'\\')) => {
                            response
                                .extend_from_slice(&file[start_byte.take().unwrap()..position - 1]);
                            start_byte = Some(position);
                        }
                        _ => {
                            response.extend_from_slice(&file[start_byte.take().unwrap()..position]);
                            placeholder_start = position;
                            stage = Stage::Placeholder;
                        }
                    }
                }
            }
            Stage::Placeholder if escaped != 1 => {
                // If placeholder closed
                if byte == b']' {
                    // Check if name is longer than empty
                    if position.checked_sub(placeholder_start + 3).is_some() {
                        // Good; we have UTF-8
                        if let Ok(key) = str::from_utf8(&file[placeholder_start + 2..position]) {
                            // If it is a valid template?
                            if let Some(template) = cache.resolve_template(host, key, &files).await
                            {
                                response.extend_from_slice(&template);
                            }
                        }
                    }
                    start_byte = Some(position + 1);
                    // Set stage to accept new text
                    stage = Stage::Text;
                }
            }
            Stage::Placeholder => {}
        }

        // Do we escape?
        if is_escape {
            escaped += 1;
            if escaped == 2 {
                escaped = 0;
            }
        } else {
            escaped = 0;
        }
    }

    if let Some(start_byte) = start_byte {
        response.extend_from_slice(&file[start_byte..]);
    }

    *body = utils::BytesCow::Mut(response)
}
fn path(host: &Host, file: &str) -> CompactString {
    utils::make_path(&host.path, "templates", file, None)
}
fn extract_templates(file: Bytes) -> TemplateMap {
    let mut templates = HashMap::with_capacity(16);

    let mut stage = Stage::Text;
    let mut placeholder_start = 0;
    let mut escaped = 0;
    let mut start_byte = Some(0);
    let mut name: Option<&str> = None;
    let mut newline_size = 1;

    for (position, byte) in file.iter().copied().enumerate() {
        if byte == CR {
            newline_size = 2;
        }
        let is_escape = byte == b'\\';

        match stage {
            Stage::Text => {
                if file[position..].starts_with(b"$[") {
                    let previous = &file[position.saturating_sub(2)..position];
                    let a = if previous.len() == 1 {
                        None
                    } else {
                        previous.first().copied()
                    };
                    let b = previous.last().copied();
                    let end = match (a, b) {
                        (Some(b'\\'), Some(b'\\')) => Some(position - 1),
                        (_, Some(b'\\')) => None,
                        _ => Some(position),
                    };
                    if let Some(end) = end {
                        let end = end.saturating_sub(newline_size);
                        if let Some(name) = name.take() {
                            let start = start_byte.take().unwrap();
                            templates.insert(
                                name.to_compact_string(),
                                file.slice(start..end.max(start)),
                            );
                        }
                        placeholder_start = position;
                        stage = Stage::Placeholder;
                    }
                }
            }
            Stage::Placeholder if escaped != 1 => {
                // If placeholder closed
                if byte == b']' {
                    // Check if name is longer than empty
                    if position.checked_sub(placeholder_start + 3).is_some() {
                        // Good; we have UTF-8
                        if let Ok(key) = str::from_utf8(&file[placeholder_start + 2..position]) {
                            name = Some(key);
                        }
                    }
                    let ignore_after_name = if file.get(position + newline_size) == Some(&LF) {
                        newline_size
                    } else {
                        usize::from(file.get(position + 1) == Some(&SPACE))
                    };
                    start_byte = Some(position + 1 + ignore_after_name);
                    // Set stage to accept new text
                    stage = Stage::Text;
                }
            }
            Stage::Placeholder => {}
        }

        // Do we escape?
        if is_escape {
            escaped += 1;
            if escaped == 2 {
                escaped = 0;
            }
        } else {
            escaped = 0;
        }
    }
    if let Some(name) = name.take() {
        let mut trim = 0;
        if file.get(file.len().saturating_sub(2)) == Some(&CR) {
            trim += 1;
        }
        if file.get(file.len().saturating_sub(1)) == Some(&LF) {
            trim += 1;
        }
        templates.insert(
            name.to_compact_string(),
            file.slice(start_byte.take().unwrap()..file.len() - trim),
        );
    }

    templates
}
