use pulldown_cmark::{CodeBlockKind, CowStr, Event, Tag};
use syntect::easy::HighlightLines;
use syntect::highlighting::{Color, FontStyle, Style, ThemeSet};
use syntect::parsing::SyntaxSet;
use syntect::util::LinesWithEndings;

lazy_static::lazy_static! {
    static ref SETS: (SyntaxSet, ThemeSet) = {
        let ss = SyntaxSet::load_defaults_newlines();
        let ts = ThemeSet::load_defaults();
        (ss, ts)
    };
}

pub(crate) struct SyntaxPreprocessor<'a, I: Iterator<Item = Event<'a>>> {
    pub(crate) parent: I,
    pub(crate) theme: &'a str,
}

impl<'a, I: Iterator<Item = Event<'a>>> Iterator for SyntaxPreprocessor<'a, I> {
    type Item = Event<'a>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let lang = match self.parent.next()? {
            Event::Start(Tag::CodeBlock(CodeBlockKind::Fenced(lang))) if !lang.is_empty() => lang,
            other => return Some(other),
        };

        let next = self.parent.next();
        let code = match next {
            Some(Event::Text(c)) => {
                let mut code = c;
                loop {
                    match self.parent.next() {
                        Some(Event::Text(ref c)) => {
                            code = {
                                let mut s = code.into_string();
                                s.push_str(c);
                                CowStr::Boxed(s.into())
                            }
                        }
                        Some(Event::End(Tag::CodeBlock(_))) | None => break,
                        Some(e) => {
                            return Some(Event::Text(
                                format!("Unexpected markdown event {:#?}", e).into(),
                            ))
                        }
                    }
                }
                code
            }
            Some(Event::End(Tag::CodeBlock(_))) | None => CowStr::Borrowed(""),
            Some(e) => {
                return Some(Event::Text(
                    format!("Unexpected markdown event {:#?}", e).into(),
                ))
            }
        };

        let mut html = String::with_capacity(code.len() + code.len() / 4 + 60);

        let (ss, ts) = &*SETS;
        // BOUNDS: we only allow values in the parser as specified by
        // https://docs.rs/syntect/5.0.0/syntect/highlighting/struct.ThemeSet.html
        let theme = &ts.themes[self.theme];

        html.push_str("<pre");
        if let Some(col) = theme.settings.background {
            html.push_str(" style=\"background-color:");
            write_css_color(&mut html, col);
            html.push_str(";\"");
        }
        html.push_str("><code class=\"language-");
        html.push_str(lang.as_ref());
        html.push_str("\">");

        let syntax_lang = match lang.as_ref() {
            "typescript" | "ts" | "jsx" => "javascript",
            // this seems to work best
            "ini" | "toml" => "sh",
            "shell" | "bash" | "fish" | "zsh" => "sh",
            "ron" => "rust",
            l => l,
        };

        let syntax = ss
            .find_syntax_by_token(syntax_lang)
            .or_else(|| ss.find_syntax_by_first_line(code.lines().next().unwrap_or("")));
        if let Some(syntax) = syntax {
            let mut highlighter = HighlightLines::new(syntax, theme);
            let lines = LinesWithEndings::from(&code);

            let mut last_style = Style::default();
            let mut first = true;

            for line in lines {
                if let Ok(tokens) = highlighter.highlight_line(line, ss) {
                    for (style, content) in tokens {
                        let new_style = style != last_style;
                        if new_style && !content.trim().is_empty() {
                            last_style = style;
                            if !first {
                                html.push_str("</span>");
                            }
                            first = false;
                            html.push_str("<span style=\"color:");
                            write_css_color(&mut html, style.foreground);
                            html.push(';');
                            if style.font_style.contains(FontStyle::ITALIC) {
                                html.push_str("font-style:italic;");
                            }
                            if style.font_style.contains(FontStyle::BOLD) {
                                html.push_str("font-weight:bold;");
                            }
                            if style.font_style.contains(FontStyle::UNDERLINE) {
                                html.push_str("text-decoration:underline;");
                            }
                            html.push_str("\">");
                        }
                        write_escaped(&mut html, content);
                    }
                } else {
                    write_escaped(&mut html, line);
                }
            }
            if !first {
                html.push_str("</span>");
            }
        } else {
            write_escaped(&mut html, &code);
        }

        html.push_str("</code></pre>");

        Some(Event::Html(html.into()))
    }
}

#[inline]
fn write_escaped(s: &mut String, part: &str) {
    let mut start = 0;

    for (idx, byte) in part.bytes().enumerate() {
        let replace = match byte {
            b'<' => "&lt;",
            b'>' => "&gt;",
            b'&' => "&amp;",
            b'"' => "&quot;",
            _ => continue,
        };
        s.push_str(&part[start..idx]);
        s.push_str(replace);

        start = idx + 1;
    }

    s.push_str(&part[start..]);
}
fn write_css_color(s: &mut String, col: Color) {
    use std::fmt::Write;
    if col.a == u8::MAX {
        write!(s, "#{:02x}{:02x}{:02x}", col.r, col.g, col.b).unwrap();
    } else {
        write!(s, "#{:02x}{:02x}{:02x}{:02x}", col.r, col.g, col.b, col.a).unwrap();
    };
}
