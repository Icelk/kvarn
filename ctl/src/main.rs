use std::path::Path;

use clap::{Arg, ValueHint};
use log::error;

const ABOUT: &str = "\nCommunicate with Kvarn instances.\n\
Use the `KVARNCTL_LOG` environment variable to set verbosity. \
Levels `info`, `warn`, `error`, and `off` are available.\n\
\n\
A list of common commands can be found at the GitHub or using the shell completion.\n\
\n\
The exit status means: 0 for success; 1 for a error from the target Kvarn instance; \
2 for communication errors, such as insufficient privileges; 3 for when the socket isn't found; \
4 means the first space-separated word of the response is unrecognized; \
5 signals an empty response; and 6 is for when the response is binary data.";

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
                    If the path is relative, /run/ is prepended.",
                )
                .value_name("UNIX SOCKET")
                .value_hint(ValueHint::FilePath)
                .default_value("kvarn.sock"),
        )
        .arg(
            Arg::new("silent")
                .short('s')
                .long("quiet")
                .help("Silence output"),
        )
        .arg(
            Arg::new("accept-not-found")
                .short('i')
                .long("accept-not-found")
                .help("Consider 'not found' error to be a success."),
        )
        .arg(
            Arg::new("wait")
                .short('w')
                .long("wait")
                .help(
                    "Waits for Kvarn to turn off. This doesn't get affected by reloads. \
                    If no Kvarn instance is running, \
                    this will wait for a) one to start and b) for it to turn off.",
                )
                .conflicts_with("command"),
        )
        .arg(
            Arg::new("explicit_command")
                .takes_value(true)
                .value_hint(ValueHint::Other)
                .value_name("COMMAND")
                .short('c')
                .help(
                    "The command to send to Kvarn. \
                    You can omit `-c` when COMMAND isn't a special subcommand.",
                ),
        )
        .arg(
            Arg::new("command")
                .takes_value(true)
                .value_hint(ValueHint::Other)
                .value_name("COMMAND"),
        )
        .arg(
            Arg::new("args")
                .value_name("ARGUMENTS")
                .takes_value(true)
                .multiple_values(true)
                .value_hint(ValueHint::Other),
        );

    command = clap_autocomplete::add_subcommand(command);

    let command_error = command.error(
        clap::ErrorKind::MissingRequiredArgument,
        "COMMAND is required unless --wait or complete is used",
    );

    let mut shell_completion_command = command.clone();
    {
        shell_completion_command = shell_completion_command
            .subcommand(
                clap::Command::new("wait")
                    .disable_help_flag(true)
                    .disable_version_flag(true)
                    .about("Waits for Kvarn to shut down. Consider using the --wait flag instead."),
            )
            .subcommand(
                clap::Command::new("shutdown")
                    .disable_help_flag(true)
                    .disable_version_flag(true)
                    .about(
                        "Tell Kvarn to perform a shutdown, \
                        often implemented as a graceful shutdown.",
                    ),
            )
            .subcommand(
                clap::Command::new("ping")
                    .disable_help_flag(true)
                    .disable_version_flag(true)
                    .about("Ping Kvarn with a message. It will send back the same message.")
                    .arg(
                        Arg::new("args")
                            .takes_value(true)
                            .multiple_values(true)
                            .value_name("CONTENT"),
                    ),
            )
            .subcommand(
                clap::Command::new("reload")
                    .disable_help_flag(true)
                    .disable_version_flag(true)
                    .about(
                        "Restart Kvarn with 0 downtime. \
                        Put simply, it replaces itself with the current version of the executable.",
                    ),
            )
            .subcommand(
                clap::Command::new("clear")
                    .disable_help_flag(true)
                    .disable_version_flag(true)
                    .about("Clears caches.")
                    .subcommand(
                        clap::Command::new("all")
                            .about("Clears all caches.")
                            .disable_help_flag(true)
                            .disable_version_flag(true),
                    )
                    .subcommand(
                        clap::Command::new("files")
                            .about("Clears all file caches.")
                            .disable_help_flag(true)
                            .disable_version_flag(true),
                    )
                    .subcommand(
                        clap::Command::new("responses")
                            .about("Clears all response caches.")
                            .disable_help_flag(true)
                            .disable_version_flag(true),
                    )
                    .subcommand(
                        clap::Command::new("file")
                            .disable_help_flag(true)
                            .disable_version_flag(true)
                            .about("Clear a specific file.")
                            .arg(
                                Arg::new("host")
                                    .required(true)
                                    .help("The host of the cache to remove the file from.")
                                    .value_hint(ValueHint::Other)
                                    .takes_value(true)
                                    .value_name("HOST"),
                            )
                            .arg(
                                Arg::new("file")
                                    .required(true)
                                    .help(
                                        "The file to remove. This is often relative \
                                      (e.g. '../icelk.dev/public/index.html').",
                                    )
                                    .value_hint(ValueHint::FilePath)
                                    .takes_value(true)
                                    .value_name("FILE"),
                            ),
                    )
                    .subcommand(
                        clap::Command::new("response")
                            .disable_help_flag(true)
                            .disable_version_flag(true)
                            .about("Clear a specific response.")
                            .arg(
                                Arg::new("host")
                                    .required(true)
                                    .help("The host of the cache to remove the response from.")
                                    .value_hint(ValueHint::Other)
                                    .takes_value(true)
                                    .value_name("HOST"),
                            )
                            .arg(
                                Arg::new("file")
                                    .required(true)
                                    .help("The response to remove (e.g. '/index.html').")
                                    .value_hint(ValueHint::Other)
                                    .takes_value(true)
                                    .value_name("RESPONSE"),
                            ),
                    ),
            );
    }
    let matches = command.get_matches();

    if let Some(result) = clap_autocomplete::test_subcommand(&matches, shell_completion_command) {
        if let Err(err) = result {
            eprintln!("Insufficient permissions: {err}");
            std::process::exit(1);
        } else {
            std::process::exit(0);
        }
    }

    let path = Path::new("/run").join(
        matches
            .value_of("path")
            .expect("we provided a default path value"),
    );

    if matches.is_present("wait") {
        let mut found = false;
        loop {
            match request(b"wait", &path, false).await {
                Ok(_) => found = true,
                Err(status) => match status {
                    3 if found => break,
                    3 if !found => {}
                    _ => std::process::exit(status),
                },
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        // exit
        return;
    };

    let message = matches
        .values_of("args")
        .map(|args| {
            args.fold(
                {
                    let mut s = String::new();
                    kvarn_utils::encode_quoted_str(
                        matches
                            .value_of("command")
                            .expect("the command is required"),
                        &mut s,
                    );
                    s
                },
                |mut acc, arg| {
                    acc.push(' ');
                    kvarn_utils::encode_quoted_str(arg, &mut acc);
                    acc
                },
            )
        })
        .unwrap_or_else(|| {
            matches
                .value_of("command")
                .or_else(|| matches.value_of("explicit_command"))
                .unwrap_or_else(|| command_error.exit())
                .to_owned()
        });

    let accept_not_found = matches.is_present("accept-not-found");

    match request(message.as_bytes(), &path, !accept_not_found).await {
        Ok(args) if !matches.is_present("silent") => println!("{args}"),
        Ok(_) => {}
        Err(3) if accept_not_found => {}
        Err(status) => std::process::exit(status),
    }
}

async fn request(message: &[u8], path: &Path, err_not_found: bool) -> Result<String, i32> {
    let status = match kvarn_signal::unix::send_to(message, &path).await {
        kvarn_signal::unix::Response::NotFound => {
            if err_not_found {
                error!(
                    "A Kvarn instance isn't running at the specified path ({}).",
                    path.display()
                );
            }
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
                        return Ok(args);
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
    Err(status)
}
