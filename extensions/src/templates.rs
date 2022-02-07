use crate::*;

pub fn templates(mut data: PresentDataWrapper) -> RetFut<()> {
    box_fut!({
        let data = unsafe { data.get_inner() };
        let bytes = handle_template(data.args(), data.response().body(), data.host()).await;
        *data.response_mut().body_mut() = bytes;
    })
}

pub async fn handle_template(
    arguments: &utils::PresentArguments,
    file: &[u8],
    host: &Host,
) -> Bytes {
    let now = Instant::now();
    let mut file_contents = Vec::with_capacity(arguments.iter().count());
    for argument in arguments.iter().rev() {
        let file = read_template_file(argument, host).await;
        if let Some(file) = file {
            file_contents.push(file);
        }
    }

    // Get templates, from cache or file
    let templates = collect_templates(file_contents.iter().map(|b| &b[..]));

    #[derive(Eq, PartialEq)]
    enum Stage {
        Text,
        Placeholder,
    }

    // Remove first line if it contains "tmpl-ignore", for formatting quirks.
    let mut file = file;
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
            // If in text stage, check for left bracket. Then set the variables for starting identifying the placeholder for template
            // Push the current byte to response, if not start of placeholder
            Stage::Text if (escaped == 0 && !is_escape) || escaped == 1 => {
                if byte == L_SQ_BRACKET && escaped != 1 {
                    placeholder_start = position;
                    stage = Stage::Placeholder;
                    response.extend_from_slice(&file[start_byte.take().unwrap()..position]);
                }
            }
            Stage::Placeholder if escaped != 1 => {
                // If placeholder closed
                if byte == R_SQ_BRACKET {
                    // Check if name is longer than empty
                    if position.checked_sub(placeholder_start + 2).is_some() {
                        // Good; we have UTF-8
                        if let Ok(key) = str::from_utf8(&file[placeholder_start + 1..position]) {
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
            Stage::Text
                if (escaped > 1 || (escaped == 0 && is_escape))
                    && file
                        .get(position + 1..position + 2)
                        .map_or(false, |range| range != [L_SQ_BRACKET]) => {}
            // Else, it's a escaping character!
            _ => {
                if let Some(sb) = start_byte.take() {
                    response.extend_from_slice(&file[sb..position]);
                    start_byte = Some(position + 1);
                }
            }
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

    println!("Templates took {}µs", now.elapsed().as_micros());
    response.freeze()
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
            warn!("Requested template file doesn't exist.");
            None
        }
    }
}
fn extract_templates(file: &[u8]) -> HashMap<&str, &[u8]> {
    let mut templates = HashMap::with_capacity(16);

    let mut last_was_lf = true;
    let mut ignore_after_name = 0;
    let mut escape = 0_u8;
    let mut name_start = 0_usize;
    let mut name_end = 0_usize;
    let mut newline_size = 1;
    let mut start_byte = Some(0);

    for (position, byte) in file.iter().copied().enumerate() {
        let defined_name = name_end > name_start;
        let in_name = name_start >= name_end;
        // Ignore all CR characters
        if defined_name && byte == CR {
            newline_size = 2;
            continue;
        }
        if escape == 1 {
            // Check escape
            if byte == ESCAPE {
                escape += 1;
            } else {
                escape = 0;
            }
            continue;
        }

        // If previous char was \, escape!
        // New template, process previous!
        if last_was_lf && byte == L_SQ_BRACKET {
            // If name is longer than empty
            if name_end.checked_sub(name_start + 2).is_some() {
                // Check if we have a valid UTF-8 string
                if let Ok(name) = str::from_utf8(&file[name_start + 1..name_end - 1]) {
                    let mut end = position.saturating_sub(newline_size);
                    if file[position.saturating_sub(1)] == ESCAPE {
                        end = end.saturating_sub(1);
                    }
                    // Then insert template; name we got from previous step, then bytes from where the previous template definition ended, then our current position, just before the start of the next template
                    // Returns a byte-slice of the file
                    templates.insert(name, &file[start_byte.unwrap()..end]);
                    name_end = 0;
                    name_start = 0;
                    start_byte = None;
                }
            }
            if name_end >= name_start {
                // Set start of template name to now
                name_start = position;
            }
            continue;
        } else if byte == L_SQ_BRACKET {
        }
        // Check escape
        if byte == ESCAPE {
            escape += 1;
        } else {
            escape = 0;
        }
        if in_name && byte == R_SQ_BRACKET {
            name_end = position + 1;
            // Check if value comes after newline, space, or right after. Then remove the CRLF/space from template value
            ignore_after_name = if file.get(name_end + newline_size - 1) == Some(&LF) {
                newline_size
            } else if file.get(name_end) == Some(&SPACE) {
                1
            } else {
                0
            };
            start_byte = Some(position + ignore_after_name + 1);
        }
        if !(byte == SPACE || byte == TAB) {
            last_was_lf = byte == LF;
        }
        if !in_name && ignore_after_name > 0 {
            ignore_after_name -= 1;
            continue;
        }
    }
    // Because we add the definitions in the start of the new one, check for last in the end of file
    if name_end.checked_sub(name_start + 2).is_some() {
        if let Ok(name) = str::from_utf8(&file[name_start + 1..name_end - 1]) {
            if let Some(start_byte) = start_byte {
                let mut end = file.len();
                if file.ends_with(&[LF]) {
                    end -= 1;
                }
                if file.ends_with(&[CR]) {
                    end -= 1;
                }
                templates.insert(name, &file[start_byte..end]);
            }
        }
    }

    templates
}
