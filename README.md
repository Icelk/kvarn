[![crates.io version](https://img.shields.io/crates/v/kvarn)](https://crates.io/crates/kvarn)
![lines of code](https://tokei.rs/b1/github/Icelk/kvarn?style=flat)
[![license](https://img.shields.io/github/license/Icelk/kvarn)](#contributing)
[![CI status](https://img.shields.io/github/actions/workflow/status/Icelk/kvarn/main.yml?branch=main)](https://github.com/Icelk/kvarn/actions)
[![open issues](https://img.shields.io/github/issues-raw/Icelk/kvarn)](https://github.com/Icelk/kvarn/issues)
[![dependency status](https://img.shields.io/deps-rs/repo/github/Icelk/kvarn)](https://deps.rs/repo/github/Icelk/kvarn)
[![commit activity](https://img.shields.io/github/commit-activity/m/Icelk/kvarn?label=commits)](https://github.com/Icelk/kvarn/tree/main/)

<img align="right" width="25%" src="https://kvarn.org/logo.svg">

# [Kvarn](https://kvarn.org/)

<blockquote style="display: inline-block; margin: 0 1rem">
    <b
        >A forward-thinking fast web server designed to fit
        <i>your</i> needs, efficiently.</b
    >
</blockquote>
<p>
    Kvarn is a <a href="https://rust-lang.org">rusty</a>,
    <a href="https://github.com/Icelk/kvarn/blob/main/LICENSE"
        >open-source</a
    >, extendable web application framework with
    <a href="https://kvarn.org/extensions/">native async everywhere</a>;
    <a href="https://kvarn.org/features/#graceful-shutdown--handover"
        >zero downtime</a
    >; and
    <a href="https://kvarn.org/features/#sane-defaults"
        >safe &amp; fast defaults</a
    >.
</p>
<p>
    Kvarn is batteries-included (optional defaults) with support for
    <b>automatic HTTPS certificates</b>, <b>HTTP/3</b>, io_uring everywhere,
    reverse proxying, auto HTTP/2 push, in-memory caching (proper cache
    invalidation), server communication provided by
    <a href="https://github.com/Icelk/kvarn/tree/main/ctl/">a simple CLI</a
    >, and easy website creation through Markdown and
    <a href="https://github.com/Icelk/kvarn/tree/main/chute/">Chute</a>.
</p>

If you're looking for an **executable** to run your webserver with, see [Mölla](https://github.com/Icelk/moella).
Using Mölla, you can configure your host(s), add a search engine, authentication, and other parts of the
[Kvarn ecosystem](https://kvarn.org/ecosystem/). More info is available on [the website](https://kvarn.org/moella/).

See the [changelog](CHANGELOG.md) or visit [our website](https://kvarn.org/) for more info.

# Current state

A stable API is available and the crate is on [crates.io](https://crates.io/crates/kvarn).
You can view the latest documentation [online](https://doc.kvarn.org).

When using Mölla, you get access to all of Kvarn's extensions and most of it's features.
If you need to develop custom extension (like [those on icelk.dev](https://github.com/Icelk/icelk.dev/blob/main/server/src/main.rs#L44-L573))
you need to compile Kvarn yourself. Luckily,
[Mölla makes it easy to add custom extensions](https://github.com/Icelk/icelk.dev/blob/659df7f19b2ac22efbe4d20f0978c9f58964c76b/server/src/main.rs#L13-L21).

To use the latest and greatest you can add Kvarn as a git dependency, though the latest version is recommended:

```ini
[dependencies]
kvarn = { git = "https://github.com/Icelk/kvarn" }
```

## Dependencies

To increase security, build-times, reliability, and speed, I use dependencies sparingly.

The two heavy-hitters are `tokio` (async runtime for async networking, file access, and extensions) and `rustls` (for encryption, optional if you want to run a unsafe (often local) web server).
`brotli` and `flate2` are enabled by default to provide compression, but can be turned off.
`h2` provides optional (but _strongly preferred_) support for the HTTP/2 protocol.

See [kvarn.org](https://kvarn.org/cargo-features.) for more details.

## Pushing to production

Take a look at the [sample.service](https://github.com/Icelk/kvarn/blob/main/sample.service)
for how to configure systemd to use [kvarnctl](https://kvarn.org/ctl/) to manage Kvarn.

You can now use `systemctl --user reload kvarn` or similar to reload the server
if you've changed the config or recompiled (if that's your thing).
This ensures ([on Unix](https://kvarn.org/shutdown-handover.#handover)) **NO downtime**. Not even a millisecond.

# Installation

[Mölla](https://github.com/Icelk/moella#installation) is the recommended way to get started with Kvarn.
You can download it and other Kvarn tools (`kvarnctl` & `chute`)
for Linux and macOS at [the Releases page](https://github.com/Icelk/moella/releases).

For Kvarn chute downloads for Linux, go [here](https://github.com/Icelk/kvarn/actions/workflows/chute.yml)
and download the artefact from the topmost job.

`kvarnctl` is also available as [CI builds](https://github.com/Icelk/kvarn/actions/workflows/kvarnctl.yml).

# Documentation

Documentation of the main branch can be found at [doc.kvarn.org](https://doc.kvarn.org/).

To document with information on which cargo features enables the code,
set the environment variable `RUSTDOCFLAGS` to `--cfg docsrs`
(e.g. in Fish `set -x RUSTDOCFLAGS "--cfg docsrs"`)
and then run `cargo +nightly doc`.

# Changelog

See the [changelog](https://github.com/Icelk/kvarn/blob/main/CHANGELOG.md).

# Contributing

This library, and all other sub-projects in this repository,
are distributed under the Apache License 2.0.
So must all contributions also be.

All rights are reserved for images and logos unless explicitly stated otherwise.
You are free to use them if reasonable credit is given. I reserve the right to order you to remove any usage at will.
