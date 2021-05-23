use crate::*;


    pub fn templates(mut data: PresentDataWrapper) -> RetFut<()> {
        box_fut!({
            let data = unsafe { data.get_inner() };
            let bytes = Bytes::copy_from_slice(
                &handle_template(data.args(), &data.response().body(), data.host()).await,
            );
            *data.response_mut().body_mut() = bytes;
        })
    }

    pub async fn handle_template(
        arguments: &PresentArguments,
        file: &[u8],
        host: &Host,
    ) -> Vec<u8> {
        // Get templates, from cache or file
        let templates = read_templates(arguments.iter().rev(), host).await;

        #[derive(Eq, PartialEq)]
        enum Stage {
            Text,
            Placeholder,
        }

        let mut response = Vec::with_capacity(file.len() * 2);

        let mut stage = Stage::Text;
        let mut placeholder_start = 0;
        let mut escaped = 0;
        for (position, byte) in file.iter().enumerate() {
            let is_escape = *byte == ESCAPE;

            match stage {
                // If in text stage, check for left bracket. Then set the variables for starting identifying the placeholder for template
                // Push the current byte to response, if not start of placeholder
                Stage::Text if (escaped == 0 && !is_escape) || escaped == 1 => {
                    if *byte == L_SQ_BRACKET && escaped != 1 {
                        placeholder_start = position;
                        stage = Stage::Placeholder;
                    } else {
                        response.push(*byte);
                    }
                }
                Stage::Placeholder if escaped != 1 => {
                    // If placeholder closed
                    if *byte == R_SQ_BRACKET {
                        // Check if name is longer than empty
                        if position.checked_sub(placeholder_start + 2).is_some() {
                            // Good; we have UTF-8
                            if let Ok(key) = str::from_utf8(&file[placeholder_start + 1..position])
                            {
                                // If it is a valid template?
                                // Frick, we have to own the value for it to be borrow for Arc<String>, no &str here :(
                                if let Some(template) = templates.get(&key.to_owned()) {
                                    // Push template byte-slice to the response
                                    for byte in &**template {
                                        response.push(*byte);
                                    }
                                }
                            }
                        }
                        // Set stage to accept new text
                        stage = Stage::Text;
                    }
                }
                // Else, it's a escaping character!
                _ => {}
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
        response
    }
    async fn read_templates<'a, I: Iterator<Item = &'a str>>(
        files: I,
        host: &Host,
    ) -> HashMap<String, Vec<u8>> {
        let mut templates = HashMap::with_capacity(32);

        for template in files {
            if let Some(map) = read_templates_from_file(template, host).await {
                for (key, value) in map.into_iter() {
                    templates.insert(key, value);
                }
            }
        }

        templates
    }
    async fn read_templates_from_file(
        template_set: &str,
        host: &Host,
    ) -> Option<HashMap<String, Vec<u8>>> {
        let path = utility::make_path(&host.path, "templates", template_set, None);

        // The template file will be access several times.
        match read_file_cached(&path, &host.file_cache).await {
            Some(file) => {
                let templates = extract_templates(&file[..]);
                Some(templates)
            }
            None => None,
        }
    }
    fn extract_templates(file: &[u8]) -> HashMap<String, Vec<u8>> {
        let mut templates = HashMap::with_capacity(16);

        let mut last_was_lf = true;
        let mut escape = false;
        let mut name_start = 0;
        let mut name_end = 0usize;
        let mut newline_size = 1;
        for (position, byte) in file.iter().enumerate() {
            // Ignore all CR characters
            if *byte == CR {
                newline_size = 2;
                continue;
            }
            // Ignore all whitespace
            if *byte == SPACE || *byte == TAB {
                continue;
            }
            // If previous char was \, escape!
            // New template, process previous!
            if !escape && last_was_lf && *byte == L_SQ_BRACKET {
                // If name is longer than empty
                if name_end.checked_sub(name_start + 2).is_some() {
                    // Check if we have a valid UTF-8 string
                    if let Ok(name) = str::from_utf8(&file[name_start + 1..name_end - 1]) {
                        // Check if value comes after newline, space, or right after. Then remove the CRLF/space from template value
                        let add_after_name = if file.get(name_end + newline_size - 1) == Some(&LF) {
                            newline_size
                        } else if file.get(name_end) == Some(&SPACE) {
                            1
                        } else {
                            0
                        };
                        // Then insert template; name we got from previous step, then bytes from where the previous template definition ended, then our current position, just before the start of the next template
                        // Returns a byte-slice of the file
                        templates.insert(
                            name.to_owned(),
                            file[name_end + add_after_name..position - newline_size].to_vec(),
                        );
                    }
                }
                // Set start of template name to now
                name_start = position;
            }
            if *byte == R_SQ_BRACKET {
                name_end = position + 1;
            }

            last_was_lf = *byte == LF;
            escape = *byte == ESCAPE;
        }
        // Because we add the definitions in the start of the new one, check for last in the end of file
        if name_end.checked_sub(name_start + 2).is_some() {
            if let Ok(name) = str::from_utf8(&file[name_start + 1..name_end - 1]) {
                // Check if value comes after newline, space, or right after. Then remove the CRLF/space from template value
                let add_after_name = if file.get(name_end + newline_size - 1) == Some(&LF) {
                    newline_size
                } else if file.get(name_end) == Some(&SPACE) {
                    1
                } else {
                    0
                };
                templates.insert(
                    name.to_owned(),
                    file[name_end + add_after_name..file.len() - newline_size].to_vec(),
                );
            }
        }
        templates
    }
