use clap::{Arg, ArgAction, ArgGroup, Command};
use kvarn_utils::prelude::*;
use std::env;

use crate::lib::ContinueBehaviour;
pub mod lib;

const HEADER_PRE_META: &[u8] = b"!> tmpl standard.html markdown.html\n$[head]";
const HEADER_POST_META: &[u8] =
    b"$[dependencies]$[md-imports]$[close-head]$[navigation]\n<main><md>";
const FOOTER: &[u8] = b"</md></main>\n$[footer]\n";
const IGNORED_EXTENSIONS: &[&str] = &["hide"];

fn main() {
    env_logger::init_from_env("CHUTE_LOG");

    info!("Starting Kvarn Markdown to HTML converter.");

    let mut command = Command::new("Kvarn Chute")
        .bin_name("chute")
        .author(clap::crate_authors!())
        .version(clap::crate_version!())
        .about(clap::crate_description!())
        .long_about(
            "Use the `CHUTE_LOG` environment variable to adjust the verbosity. \
            `CHUTE_LOG=off chute` disables logging, \
            disregarding errors.",
        )
        .arg(
            Arg::new("PATHS")
                .help("Paths to process/watch")
                .required(true)
                .default_value(".")
                .value_hint(clap::ValueHint::AnyPath)
                .num_args(1..),
        )
        .arg(
            Arg::new("continue")
                .help("Continue with the defaults on prompts.")
                .short('c')
                .action(ArgAction::SetTrue)
                .long("continue"),
        )
        .arg(
            Arg::new("yes")
                .help("Continue with `yes` on all prompts.")
                .short('y')
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("no")
                .help("Continue with `no` on all prompts.")
                .short('n')
                .action(ArgAction::SetTrue),
        )
        .group(
            ArgGroup::new("continue_behaviour")
                .arg("continue")
                .arg("yes")
                .arg("no"),
        );

    #[cfg(feature = "completion")]
    {
        command = clap_autocomplete::add_subcommand(command);
    }

    #[cfg(feature = "completion")]
    let command_copy = command.clone();

    let matches = command.get_matches();

    #[cfg(feature = "completion")]
    {
        if let Some(result) = clap_autocomplete::test_subcommand(&matches, command_copy) {
            if let Err(err) = result {
                eprintln!("Insufficient permissions: {err}");
                std::process::exit(1);
            } else {
                std::process::exit(0);
            }
        }
    }

    let paths = matches.get_many::<String>("PATHS").unwrap_or_else(|| {
        lib::exit_with_message(
            "Please enter a path to a file to convert or directory to watch as the first argument.",
        )
    });

    let continue_behaviour = {
        if matches.get_flag("continue") {
            ContinueBehaviour::Default
        } else if matches.get_flag("yes") {
            ContinueBehaviour::Yes
        } else if matches.get_flag("no") {
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
