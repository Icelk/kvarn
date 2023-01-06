use crate::*;

#[derive(Eq, PartialEq)]
enum Stage {
    Text,
    Placeholder,
}

pub fn templates<'a>(data: &'a mut extensions::PresentData<'a>) -> RetFut<'a, ()> {
    box_fut!({
        handle_template(&data.args, data.response.body_mut(), data.host).await;
    })
}

pub async fn handle_template(
    arguments: &utils::PresentArguments,
    body: &mut utils::BytesCow,
    host: &Host,
) {
    let mut file_contents = Vec::with_capacity(arguments.iter().count());
    for argument in arguments.iter().rev() {
        let file = read_template_file(argument, host).await;
        if let Some(file) = file {
            file_contents.push(file);
        }
    }

    // Get templates, from cache or file
    let templates = collect_templates(file_contents.iter().map(|b| &b[..]));

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
        let is_escape = byte == ESCAPE;

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
                if byte == R_SQ_BRACKET {
                    // Check if name is longer than empty
                    if position.checked_sub(placeholder_start + 3).is_some() {
                        // Good; we have UTF-8
                        if let Ok(key) = str::from_utf8(&file[placeholder_start + 2..position]) {
                            // If it is a valid template?
                            if let Some(template) = templates.get(key) {
                                response.extend_from_slice(template);
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
fn collect_templates<'a, I: Iterator<Item = &'a [u8]>>(files: I) -> HashMap<&'a str, &'a [u8]> {
    let mut templates = HashMap::with_capacity(32);

    for file in files {
        for (key, value) in extract_templates(file).into_iter() {
            templates.insert(key, value);
        }
    }

    templates
}
async fn read_template_file<'a>(file: &str, host: &'a Host) -> Option<Bytes> {
    let path = utils::make_path(&host.path, "templates", file, None);

    // The template file will be access several times.
    match read_file_cached(&path, host.file_cache.as_ref()).await {
        Some(file) => Some(file),
        None => {
            warn!("Requested template file {:?} doesn't exist.", file);
            None
        }
    }
}
fn extract_templates(file: &[u8]) -> HashMap<&str, &[u8]> {
    let mut templates = HashMap::with_capacity(16);

    let mut stage = Stage::Text;
    let mut placeholder_start = 0;
    let mut escaped = 0;
    let mut start_byte = Some(0);
    let mut name = None;
    let mut newline_size = 1;

    for (position, byte) in file.iter().copied().enumerate() {
        if byte == CR {
            newline_size = 2;
        }
        let is_escape = byte == ESCAPE;

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
                            templates.insert(name, &file[start..end.max(start)]);
                        }
                        placeholder_start = position;
                        stage = Stage::Placeholder;
                    }
                }
            }
            Stage::Placeholder if escaped != 1 => {
                // If placeholder closed
                if byte == R_SQ_BRACKET {
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
        templates.insert(name, &file[start_byte.take().unwrap()..file.len() - trim]);
    }

    templates
}
