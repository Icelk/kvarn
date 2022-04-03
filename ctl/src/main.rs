use clap::{Arg, ValueHint};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let mut command = clap::command!();
    command = command
        .arg(
            Arg::new("path")
                .short('p')
                .long("socket-path")
                .value_name("UNIX SOCKET")
                .value_hint(ValueHint::FilePath),
        )
        .arg(
            Arg::new("command")
                .takes_value(true)
                .value_hint(ValueHint::Other)
                .value_name("COMMAND"),
        );
    println!("Hello, world!");
}
