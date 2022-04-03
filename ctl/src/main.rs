use std::path::Path;

use clap::{Arg, ValueHint};
use log::error;

const ABOUT: &str = "Communicate with Kvarn instances.\n\
Use the `KVARNCTL_LOG` environment variable to set verbosity. \
Levels `info`, `warn`, `error`, and `off` are available.\n\
The exit status means: 0 for success; 1 for a error from the target Kvarn instance; \
2 for communication errors, such as insufficient privileges; 3 for when the socket isn't found; \
4 means the first space-separated word of the response is unrecognized; \
5 signals an empty response; and 6 is for when the response is binary data.";

fn wrap_quotes(src: &str, target: &mut String) {
    target.reserve(src.len() + 2 + 4);
    target.push('"');
    for c in src.chars() {
        match c {
            '"' => target.push_str("\\\""),
            _ => target.push(c),
        }
    }
    target.push('"');
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    env_logger::init_from_env("KVARNCTL_LOG");

    let mut command = clap::command!();
    command = command
        .about(ABOUT)
        .arg(
            Arg::new("path")
                .short('p')
                .long("socket-path")
                .help(
                    "The name of the socket to communicate over. \
                    If the path is relative, /tmp/ is prepended.",
                )
                .value_name("UNIX SOCKET")
                .value_hint(ValueHint::FilePath)
                .default_value("kvarn.sock"),
        )
        .arg(
            Arg::new("command")
                .takes_value(true)
                .value_hint(ValueHint::Other)
                .value_name("COMMAND")
                .required(true),
        )
        .arg(
            Arg::new("args")
                .value_name("ARGUMENTS")
                .takes_value(true)
                .multiple_values(true)
                .value_hint(ValueHint::Other),
        );

    let matches = command.get_matches();
    let path = Path::new("/tmp").join(
        matches
            .value_of("path")
            .expect("we provided a default path value"),
    );
    let message = matches
        .values_of("args")
        .map(|args| {
            args.fold(
                {
                    let mut s = String::new();
                    wrap_quotes(
                        matches
                            .value_of("command")
                            .expect("the command is required"),
                        &mut s,
                    );
                    s
                },
                |mut acc, arg| {
                    wrap_quotes(arg, &mut acc);
                    acc
                },
            )
        })
        .unwrap_or_else(|| {
            matches
                .value_of("command")
                .expect("the command is required")
                .to_owned()
        });

    let status = match kvarn_signal::unix::send_to(message.as_bytes(), &path).await {
        kvarn_signal::unix::Response::NotFound => {
            error!(
                "A Kvarn instance isn't running at the specified path ({}).",
                path.display()
            );
            3
        }
        kvarn_signal::unix::Response::Error => {
            error!("An error occurred when communicating with Kvarn. This may be due to insufficient privileges.");
            2
        }
        kvarn_signal::unix::Response::Data(data) => {
            if let Ok(data) = std::str::from_utf8(&data) {
                let mut iter = kvarn_utils::quoted_str_split(data);
                let command = iter.next();
                let args = kvarn_utils::join(iter, " ");
                match command.as_deref() {
                    Some("ok") => {
                        println!("{args}");
                        0
                    }
                    Some("error") => {
                        if args.trim().is_empty() {
                            error!("Kvarn returned an error.");
                        } else {
                            error!("Kvarn returned an error: {args}");
                        }
                        1
                    }
                    Some(command) => {
                        error!("The response contains an unrecognized command: {command:?} with arguments: {args}");
                        4
                    }
                    None => {
                        error!("We got an empty response.");
                        5
                    }
                }
            } else {
                error!("Response is binary data.");
                6
            }
        }
    };
    std::process::exit(status);
}
