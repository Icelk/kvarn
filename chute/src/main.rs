use clap::builder::PossibleValuesParser;
use clap::{Arg, ArgAction, ArgGroup, Command};
use kvarn_utils::prelude::*;
use std::env;

use kvarn_chute as lib;
use kvarn_chute::ContinueBehaviour;

const HEADER_PRE_META: &[u8] = b"!> tmpl standard.html markdown.html\n$[head]";
const HEADER_POST_META: &[u8] =
    b"$[dependencies]$[md-imports]$[close-head]$[navigation]\n<main><md>";
const FOOTER: &[u8] = b"</md></main>\n$[footer]\n";
const IGNORED_EXTENSIONS: &[&str] = &["hide"];

fn main() {
    let env = env_logger::Env::new().filter_or("CHUTE_LOG", "error");
    env_logger::Builder::from_env(env).init();

    info!("Starting Kvarn Markdown to HTML converter.");

    let mut command = Command::new("Kvarn Chute")
        .bin_name("chute")
        .author(clap::crate_authors!())
        .version(clap::crate_version!())
        .about(clap::crate_description!())
        .long_about(
            "Use the `CHUTE_LOG` environment variable to adjust the verbosity. \
            `CHUTE_LOG=off chute` disables logging, \
            disregarding errors.\n\
            You can write ${date} in your documents to get the date of write. \
            You can specify how the date will be formatted by ${date <format>}, \
            following https://time-rs.github.io/book/api/format-description.html.",
        )
        .arg(
            Arg::new("PATHS")
                .help("Paths to process/watch")
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
        )
        .arg(
            Arg::new("theme")
                .long("theme")
                .short('t')
                .help(
                    "Theme used for static syntax highlighting.\n\
                    See https://docs.rs/syntect/5.0.0/syntect/highlighting/struct.ThemeSet.html \
                    for all options.",
                )
                .value_parser(PossibleValuesParser::new([
                    "base16-eighties.dark",
                    "base16-ocean.dark",
                    "base16-mocha.dark",
                    "base16-ocean.light",
                    "InspiredGitHub",
                    "Solarized (dark)",
                    "Solarized (light)",
                ]))
                .default_value("base16-eighties.dark"),
        );

    #[cfg(feature = "completion")]
    {
        command = clap_autocomplete::add_subcommand(command);
    }

    #[cfg(feature = "completion")]
    let command_copy = command.clone();

    let matches = command.get_matches_mut();

    #[cfg(feature = "completion")]
    {
        if let Some(result) = clap_autocomplete::test_subcommand(&matches, command_copy) {
            if let Err(err) = result {
                eprintln!("{err}");
                std::process::exit(1);
            } else {
                std::process::exit(0);
            }
        }
    }

    let paths = matches.get_many::<String>("PATHS").unwrap_or_else(|| {
        command.print_long_help().unwrap();
        std::process::exit(1);
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

    let theme = matches
        .get_one::<String>("theme")
        .expect("We provided a default");

    for path in paths {
        let path = Path::new(path);
        match path.is_dir() {
            true => {
                let path = path.to_path_buf();
                let theme = theme.clone();
                let thread = std::thread::spawn(move || {
                    info!("Watching directory and overriding files.");
                    lib::watch(
                        &path,
                        HEADER_PRE_META,
                        HEADER_POST_META,
                        FOOTER,
                        IGNORED_EXTENSIONS,
                        continue_behaviour,
                        &theme,
                    );
                });
                threads.push(thread);
            }
            false => {
                if lib::process_document(
                    path,
                    HEADER_PRE_META,
                    HEADER_POST_META,
                    FOOTER,
                    IGNORED_EXTENSIONS,
                    continue_behaviour,
                    theme,
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
