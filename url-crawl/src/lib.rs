use select::document::Document;
use select::predicate::{Attr, Name};

/// Extracts the links from `html`.
/// This can be used to HTTP/2 push the linked resources.
///
/// Gets
/// - `<link>` nodes where `rel` != `preconnect`
/// - all nodes with a `src` attribute
///
/// ToDo: Add `background-image` and other css link detection
pub fn get_urls(html: &str) -> Vec<String> {
    let mut urls = Vec::with_capacity(512);

    let document = Document::from(html);

    // `<link>` pass
    for node in document.find(Name("link")) {
        // Disabled: Pushing only stylesheets
        if let Some("preconnect") = node.attr("rel") {
            continue;
        }
        if let Some(url) = node.attr("href") {
            urls.push(url.to_string());
        }
    }
    // // `<script>` pass
    // for node in document.find(Name("script")) {
    //     if let Some(url) = node.attr("src") {
    //         urls.push(url.to_string());
    //     }
    // }
    // // `<img>` pass
    // for node in document.find(Name("img")) {
    //     if let Some(url) = node.attr("src") {
    //         urls.push(url.to_string());
    //     }
    // }
    // // `<img>` pass
    // for node in document.find(Name("video")) {
    //     if let Some(url) = node.attr("src") {
    //         urls.push(url.to_string());
    //     }
    // }
    // `.src` pass
    for node in document.find(Attr("src", ())) {
        urls.push(node.attr("src").unwrap().to_string());
    }
    urls
}

#[cfg(test)]
mod tests {
    use crate::get_urls;

    #[test]
    fn basic_html() {
        let html = r#"
<html lang="en-GB">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=0.8, shrink-to-fit=no">
        <link rel="preconnect" href="https://fonts.gstatic.com">
        <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Roboto:400&;display=swap">
        <link rel="stylesheet" type="text/css" href="/style.css">
        <script src="/script.js" defer></script>
    </head>

    <body>
        <main style="text-align: center; background-image: url('/bg.png');">
            <a href="/posts/">Go to posts</a>
        </main>
    </body>
</html>"#;

        assert_eq!(
            get_urls(html),
            vec![
                "https://fonts.googleapis.com/css?family=Roboto:400&;display=swap".to_string(),
                "/style.css".to_string(),
                "/script.js".to_string(),
            ]
        )
    }
}
