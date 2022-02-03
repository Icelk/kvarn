use clap::{App, Arg, ArgGroup};
use kvarn_utils::prelude::*;
use std::env;

use crate::lib::ContinueBehaviour;
pub mod lib;

const HEADER_PRE_META: &[u8] = b"!> tmpl standard.html markdown.html\n[head]";
const HEADER_POST_META: &[u8] = b"[dependencies][md-imports][close-head][navigation]\n<main><md>";
const FOOTER: &[u8] = b"</md></main>\n[footer]\n";
const IGNORED_EXTENSIONS: &[&str] = &["hide"];

fn main() {
    env_logger::init_from_env("CHUTE_LOG");

    info!("Starting Kvarn Markdown to HTML converter.");

    let app = App::new("Kvarn Chute")
        .author(clap::crate_authors!())
        .version(clap::crate_version!())
        .about(clap::crate_description!())
        .long_about("Use the `CHUTE_LOG` environment variable to adjust the verbosity. `CHUTE_LOG=off chute` disables logging, disregarding errors.")
        .arg(
            Arg::new("PATHS")
                .help("Paths to process/watch")
                .required(true)
                .multiple_values(true),
        )
        .arg(
            Arg::new("continue")
                .help("Continue with the defaults on prompts.")
                .short('c')
                .long("continue"),
        )
        .arg(
            Arg::new("yes")
                .help("Continue with `yes` on all prompts.")
                .short('y'),
        )
        .arg(
            Arg::new("no")
                .help("Continue with `no` on all prompts.")
                .short('n'),
        )
        .group(
            ArgGroup::new("continue_behaviour")
                .arg("continue")
                .arg("yes")
                .arg("no"),
        );

    let matches = app.get_matches();

    let paths = matches.values_of("PATHS").unwrap_or_else(|| {
        lib::exit_with_message(
            "Please enter a path to a file to convert or directory to watch as the first argument.",
        )
    });

    let continue_behaviour = {
        if matches.is_present("continue") {
            ContinueBehaviour::Default
        } else if matches.is_present("yes") {
            ContinueBehaviour::Yes
        } else if matches.is_present("no") {
            ContinueBehaviour::No
        } else {
            ContinueBehaviour::Ask
        }
    };

    let mut threads = Vec::new();

    let mut bad_status = false;

    for path in paths {
        let path = Path::new(path);
        match path.is_dir() {
            true => {
                let path = path.to_path_buf();
                let thread = std::thread::spawn(move || {
                    info!("Watching directory and overriding files.");
                    lib::watch(
                        &path,
                        HEADER_PRE_META,
                        HEADER_POST_META,
                        FOOTER,
                        IGNORED_EXTENSIONS,
                        continue_behaviour,
                    );
                });
                threads.push(thread);
            }
            false => {
                if lib::process_document(
                    &path,
                    HEADER_PRE_META,
                    HEADER_POST_META,
                    FOOTER,
                    IGNORED_EXTENSIONS,
                    continue_behaviour,
                )
                .is_err()
                {
                    bad_status = true;
                }
                info!("Done converting CommonMark to HTML.");
            }
        }
    }

    for thread in threads {
        thread
            .join()
            .unwrap_or_else(|e| lib::exit_with_message(format!("Watch thread failed: {:?}", e)))
    }

    if bad_status {
        std::process::exit(1);
    }
}
