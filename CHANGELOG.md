# v0.6.3

Fixed compilation when the zstd feature was disabled, but other compression features were enabled.

# [v0.6.2](https://github.com/Icelk/kvarn/compare/v0.6.0...v0.6.2)

Many bugfixes to reverse proxy, including websockets finally working and body
streaming for large files (e.g. movies through Jellyfin). **Zstd** is also
supported now, and compression levels are generally more fitting.

## Added

-   Zstd compression
-   Reverse proxy body streaming for large files
-   Option to make systemd services work with a bug in io_uring
    -   Sometimes a double-free happens after Kvarn has finished. This can be
        ignored, and so a flag to ignore that was added to kvarnctl

## Improved

-   Using official Quinn instead of the kvarn fork.
    -   zero copying
    -   less allocations
    -   more robust implementation
-   Dynamic compress based on if the response is cached or not.
-   Make io_uring even faster with less allocations
-   Performance related to HTTP/1 requests and responses. Also useful for other
    HTTP versions when reverse proxy is used (HTTP/1 is used for reverse proxy).
-   Updated dependencies

## Fixed

-   **Reverse proxy websockets**.
-   Reverse proxy for Jellyfin
-   Auto cert made more robust
-   Auto cert in development behaves better
-   Auto cert private key having permission 644 instead of 600
-   kvarn_signal (used by kvarnctl) fixed commands sometimes not being sent

# v0.6.1

Hotfix related to Windows builds failing.

# [v0.6.0](https://github.com/Icelk/kvarn/compare/v0.5.0...v0.6.0)

This release adds support for HTTP/3, io_uring, automatic Let's Encrypt
certificate, and [Mölla](https://kvarn.org/moella/) is released, a server binary
which reads a config and starts Kvarn.

Kvarn is the first server with HTTP/3 AND io_uring, bringing the best possible
performance to Linux servers.

## Added

-   HTTP/3
-   [io_uring](https://en.wikipedia.org/wiki/Io_uring)
-   Automatic certificate
-   [Stream body extension](https://docs.rs/kvarn/latest/kvarn/extensions/fn.stream_body.html),
    for streaming large files which don't fit in memory.
-   Kvarn Chute built in syntax highlighting
-   A monoio-esque runtime for best web performance

## Improved

-   Internal stability
-   Performance
-   Use CompactString to reduce allocations.
-   Use MokaCache instead of a shitty hashmap. (cache invalidation is better)
-   Make CSP more flexible
-   Caching of files, based on mtime.

## Fixed

-   kvarnctl and restarts on macOS.
-   Change certificates live, in production. Enables auto certificate without
    restarting the server.

# [v0.5.0](https://github.com/Icelk/kvarn/compare/v0.4.1...v0.5.0)

This release adds support for
[WebSocket](https://doc.kvarn.org/kvarn/websocket/fn.response.html#examples)s.
It's trivial to add WebSocket support for both HTTP and HTTPS; an echo socket
takes 15 lines to implement, thanks to Kvarn's robust extension system.

A new extension has also been developed, namely `kvarn-auth`, a fast and
easy-to-configure authentication service. You just need to provide a callback
which returns whether or not the user with the provided password is authorized,
and any other data associated with that user (e.g. it's permissions).

## Added

-   Simple WebSocket integration.
-   Secure and fast
    [authentication](https://doc.icelk.dev/kvarn-auth/kvarn_auth/) for all your
    Kvarn instances. Supports multiple authentication systems per host.
-   Simpler PHP for specific paths wich need to correspond to a certain
    directory.
-   HTML id `toc` to `kvarn-chute` `${toc}` generation.

## Improved

-   URL rewrite in reverse-proxy treats backticks as quotes when adding to the
    path.
-   Various documentation improvements.
-   Don't send `vary` and `content-type` headers for responses with no body.

## Fixed

-   WebDAV methods are allowed.
-   Issues with ALPN (we didn't advertise HTTP/1.1).
-   Add `<!DOCTYPE html>` to default errors.
-   Reading HTTP/1.1 request bodies.
-   CORS preflight is by default allowed from the same site.

## Changed

-   [`CspValueSet::scheme`](https://doc.kvarn.org/kvarn/csp/struct.ValueSet.html#method.scheme)
    now takes a string.
-   The priority of the
    [`http_to_https`](https://doc.kvarn.org/kvarn/extensions/struct.Extensions.html#method.with_http_to_https_redirect)
    extension is bumped. (the cause of this was partially to have priority over
    `kvarn-auth`'s redirect to login page)

# [v0.4.1](https://github.com/Icelk/kvarn/compare/v0.4.0...v0.4.1)

## Fixed

-   Fixed panic when parsing malicious HTTP request. All crates using
    `kvarn_utils` should upgrade it to `=0.4.1` if you use the function
    `headers` and accept arbitrary input.

## Changed

-   Default path for `kvarnctl`.
    -   In root contexts, it was moved from `/tmp/kvarn.sock` to
        `/run/kvarn.sock`
    -   In user contexts, it was moved from `/tmp/kvarn.sock` to
        `/run/user/<uid>/kvarn.sock`
    -   This fixed the socket being garbage collected by the OS.

# [v0.4.0 ctl](https://github.com/Icelk/kvarn/compare/v0.3.0...v0.4.0)

A smaller release to improve the experience working with Kvarn. Notably, a
`kvarnctl` executable allows you to change a running Kvarn instance, including
restarting the server in-place, with **zero downtime**.

## Added

-   A [`kvarnctl` executable to control](https://kvarn.org/ctl/) the running
    Kvarn instance.
    -   Implement all methods used in
        [`kvarn-reference`](https://github.com/Icelk/kvarn-reference)
    -   [Plugins](https://doc.kvarn.org/kvarn/macro.plugin.html) to add
        interfaces to Kvarn which can be accessed through `kvarnctl`.
    -   Shell completion for most commonly used methods in `kvarnctl`.
-   Extension system
    [doesn't use unsafe](https://github.com/Icelk/kvarn/commit/83b5d10)!
-   Dozens of [webpages](https://github.com/Icelk/kvarn.org) to read more about
    [Kvarn](https://kvarn.org) on.
-   [Reading host names from certificate](https://doc.kvarn.org/kvarn/host/struct.Host.html#method.new_name_from_cert).
    ([commit](https://github.com/Icelk/kvarn/commit/2bb32cb))
-   [Graceful restart through systemd service](https://github.com/Icelk/kvarn/blob/main/sample.service)
-   [doc_cfg](https://doc.rust-lang.org/beta/unstable-book/language-features/doc-cfg.html)
    (implemented through use of
    [doc_auto_cfg](https://doc.rust-lang.org/beta/unstable-book/language-features/doc-auto-cfg.html)).
-   [noonce](https://kvarn.org/nonce.) implementation
-   Parallel handling of requests per connection.
-   Control over which
    [compression](https://doc.kvarn.org/kvarn/host/struct.Host.html#structfield.compression_options)
    method to prefer/use.
    ([commit](https://github.com/Icelk/kvarn/commit/7cecad8))
-   [Kvarn Search](https://github.com/Icelk/kvarn-search), an easy to integrate
    site search engine for Kvarn.
-   API to access/remove extensions after they've been mounted.
-   [Added option](https://github.com/Icelk/kvarn/commit/1b39289) to change
    directory where Kvarn gets it's error responses from.
-   [Shell completion](https://github.com/Icelk/clap_autocomplete) to all
    binaries.

## Changed

-   Constructor methods on [CORS](https://doc.kvarn.org/kvarn/cors/) and
    [CSP](https://doc.kvarn.org/kvarn/csp/).
-   Make templates use `$[]` instead of `[]`.

## Fixed

-   Correct
    [PHP/FastCGI](https://doc.kvarn.org/kvarn_extensions/php/fn.mount_php.html)
    implementation.
-   Percent decoding of requests
-   [Fixed small bug](https://github.com/Icelk/kvarn/commit/482486a2) where
    Kvarn would emit multiple `charset=utf-8` attributes for `content-type`.
-   Dependency clean-up.
-   [Proper handling of clients closing HTTP/2 streams](https://github.com/Icelk/kvarn/commit/90aae79).
-   Fix issues with several present extensions.
-   [`utils::parse::query`](https://github.com/Icelk/kvarn/commit/957b9db).
-   All components of Kvarn are now shut down when you drop Kvarn's references.
    No memory leaks.
-   Hosts are now [recognized](https://github.com/Icelk/kvarn/commit/8934160)
    even if they are accessed through their FQDN.

## Improved

-   Stability improvements
-   Production ready reverse proxy.
-   Improvements to cargo feature in [documentation](https://doc.kvarn.org).
-   Major improvements to [Chute](https://kvarn.org/chute/)
-   Removed insecure `chrono` dependency in favour of `time`.
-   Removed many redundant allocations.
-   Improve template performance.
-   Improved [`handle_cache`](https://doc.kvarn.org/kvarn/fn.handle_cache.html).
    You can now just get a response from Kvarn, with a guarantee of no error
    arising.
-   [Cache performance](https://github.com/Icelk/kvarn/commit/614f57b)
-   [Limiting performance](https://github.com/Icelk/kvarn/commit/fc704c6)
-   [Testing on CI](https://github.com/Icelk/kvarn/commit/38c7d7b) for all
    crates.
-   Debug implementations are less prone to errors and easier to maintain.

# [v0.3.0 Ext](https://github.com/Icelk/kvarn/compare/v0.2.0...v0.3.0)

This is a ~~smaller~~ less headline-feature-rich release, fixing several bugs,
increasing performance, and adding small features necessary for a _solid_ web
server.

The name comes from the current plan to move core stuff into it's own crate.

## Added

-   [Full doc coverage](https://doc.kvarn.org) (this took _way_ too long...)
-   Good test coverage
-   Proper extension macros
-   Additional server-side cache options, including parsing `cache-control`
    header
-   Cache handling of [Vary](https://kvarn.org/vary.) header (definitely the
    hardest)
-   Support for request byte ranges
-   Implement an
    [easy-to-configure proxy extension](https://doc.kvarn.org/kvarn_extensions/reverse_proxy/struct.Manager.html)
    in kvarn_extensions
-   [If-Modified-Since](https://doc.kvarn.org/kvarn/host/struct.Options.html#structfield.disable_if_modified_since)
    header to increase client cache performance
-   Smart push (so all other data isn't pushed on every request)
-   [Graceful shutdown and handover](https://kvarn.org/shutdown-handover.).
    Maintenance and updates are now a non-issue!
-   IPv6
-   [CI](https://github.com/Icelk/kvarn/actions)
-   [Content Security Policy](https://kvarn.org/csp.)

## Improved

-   `read_to_bytes()` performance

## Changed

-   Extension macros
-   Construction of a server instance
-   Move core stuff

# [v0.2.0 Tokio](https://github.com/Icelk/kvarn/compare/v0.1.0...v0.2.0)

This version HTTP/2, fast async IO, a new superior extension system, and nearly
no code left from v0.1.0! This release is now currently running
[icelk.dev](https://icelk.dev) and [kvarn.org](https://kvarn.org).

This is a _real_ performance uplift. It's essentially a complete rewrite of
Kvarn. The pages at kvarn.org, especially the one about
[extensions](https://kvarn.org/extensions/) and the
[request pipeline](https://kvarn.org/pipeline.html) should make the design
choices more clear. It should be understandable even for non-programmers and
make it easier to integrate with Kvarn.

> One other big thing is HTTP/2 Push, which makes loading web sites more than 2
> times faster. Without doing anything from your part, you can expect automatic
> push to work, resulting in the described benefits. Soon, Smart Push will be
> part of Kvarn, further increasing performance.

## Added

-   Use Tokio as the async runtime
-   [Async](https://kvarn.org/async.) io
-   [Async](https://kvarn.org/async.) extensions
-   Flexible interface for HTTP versions
-   [HTTP/2](https://kvarn.org/http2.)
-   [request limiting](https://kvarn.org/limiting.)
-   handling of HEAD HTTP method
-   more #\[inline] (better performance)
-   [Referrer header](https://doc.kvarn.org/kvarn/extensions/struct.Extensions.#method.with_no_referrer)
    in `Extensions::new()`
-   [cfg](https://kvarn.org/cargo-features.) (https, multithreading, http2)

## Changed

-   Everything else.
-   Future plan for routing and extensions

## Fixed

-   Everything.

# v0.1.0

This milestone is reached. It was the first working state of the web server.

It's slow, not having async IO except for requests; FS is utterly slow and
making any other async requests to a database or to proxy another server does
not work (technically it does, but performance is miserable).
