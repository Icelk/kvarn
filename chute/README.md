# [Kvarn Chute](https://kvarn.org/chute/)

> A chute to transport .md files to be refined by Kvarn

This is a small binary designed to convert from CommonMark to HTML using the
[`kvarn-extensions`](https://kvarn.org/ecosystem/#extensions) [template system](https://kvarn.org/features/#templates).

It supports watching a directory for changes to .md files, or simply converting a single file on command.

See [the CI on GitHub](https://github.com/Icelk/kvarn/actions/workflows/chute.yml) for Linux downloads.

# Shell completion

Using the subcommand `completion`, Chute automatically generates shell completions for your shell and tries to put them in the appropriate location.

When using Bash or Zsh, you should run Chute as root, as we need root privileges to write to their completion directories.
Alternatively, use the `--print` option to yourself write the completion file.
