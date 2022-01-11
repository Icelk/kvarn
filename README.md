[![crates.io version](https://img.shields.io/crates/v/kvarn)](https://crates.io/crates/kvarn)
![lines of code](https://img.shields.io/tokei/lines/github/Icelk/kvarn)
![license](https://img.shields.io/github/license/Icelk/kvarn)
[![CI status](https://img.shields.io/github/workflow/status/Icelk/kvarn/Continuous%20Integration)](https://github.com/Icelk/kvarn/actions)
[![open issues](https://img.shields.io/github/issues-raw/Icelk/kvarn)](https://github.com/Icelk/kvarn/issues)
[![dependency status](https://deps.rs/repo/github/Icelk/kvarn/status.svg)](https://deps.rs/repo/github/Icelk/kvarn)
[![commit activity](https://img.shields.io/github/commit-activity/m/Icelk/kvarn?label=commits)](https://github.com/Icelk/kvarn/tree/main/)

<img align="right" width="25%" src="https://kvarn.org/logo.svg">

# [Kvarn](https://kvarn.org/)

> An extensible and efficient forwards thinking web server.

Kvarn is a modular web server, designed from the ground up without excessive dependencies.
It supports several types of [extensions](https://kvarn.org/extensions/) to make it your own.

See the [roadmap](roadmap.md) or visit [kvarn.org](https://kvarn.org/) for more info.

# Current state

Now that `v0.3.0` is out, a stable API is available and the crate is on [crates.io](https://crates.io/crates/kvarn).

[At least for now](https://kvarn.org/config.) you'll have to configure Kvarn through code
(e.g. add extensions from [`kvarn_extensions`](extensions/README.md) and configuring hosts).

To use the latest and greatest
(with regular breaking changes, follow the progress at the
[reference implementation](https://github.com/Icelk/kvarn-reference) for solutions)
you can add Kvarn using this Git repo.

## Dependencies

To increase security, build-times, reliability, and speed, I use the minimal reasonable number of dependencies.

The two heavy-hitters are `tokio` (async runtime for async networking, file access, and extensions) and `rustls` (for encryption, optional if you want to run a unsafe (often local) web server).
`brotli` and `flate2` are enabled by default to provide compression, but can be turned off.
`h2` provides optional (but _strongly preferred_) support for the HTTP/2 protocol.

# Downloads

If you want to download the `.rlib` files, they are published in [actions](https://github.com/Icelk/kvarn/actions) after each good commit.
Click the topmost run for
[Kvarn](https://github.com/Icelk/kvarn/actions/workflows/main.yml) or
[Kvarn extensions](https://github.com/Icelk/kvarn/actions/workflows/extensions.yml)
and download the appropriate artefact.

For Kvarn chute downloads for Linux, go [here](https://github.com/Icelk/kvarn/actions/workflows/chute.yml)
and download the artefact from the topmost job.

# Contributing

This library, and all other sub-projects, are distributed under the Apache License 2.0.
So must all contributions also be.

Images and logos are under my copyright unless explicitly stated otherwise.
You are free to use them if reasonable credit is given. I reserve the right to order you to remove any use at will.
