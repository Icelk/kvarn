# Roadmap

This is the roadmap for future development of Kvarn.

> The work will be taking place in branches, named after the target release. The order of these feature releases are not set in stone;
> the features of 0.4.0 might come out as version 0.3.0

# v0.1.0

This milestone is reached. It was the first working state of the web server.

It's slow, not having async IO except for requests; FS is utterly slow and
making any other async requests to a database or to proxy another server does not work
(technically it does, but performance is miserable).

# v0.2.0 Tokio

We have now reached this milestone, with HTTP/2, fast async IO, a new superior extension system, and nearly no code left from v0.1.0!
This release is now currently running [icelk.dev](https://icelk.dev) and [kvarn.org](https://kvarn.org).

This is a *real* performance uplift. It's essentially a complete rewrite of Kvarn.
[extensions.md](extensions.md) and [routing.md](routing.md) are documents designed to make the server's
architecture more *transparent*. It should be understandable even for non-programmers. It should make it easier to integrate with Kvarn.

> One other big thing is HTTP/2 Push, which makes loading web sites more than 2 times faster.
> Without doing anything from your part, you can expect automatic push to work, resulting in the
> described benefits. Soon, Smart Push will be part of Kvarn, further increasing performance.

## Left to do

- [x] Tokio
- [x] Async io
- [x] Async extensions
- [x] Flexible interface for HTTP versions
- [x] HTTP/2
- [x] limiting
- [x] HEAD
- [x] check routing and extensions.md plan
- [x] more #[inline]
- [x] Referrer header in `Extensions::new()`
- [x] cfg (https, multithreading, http2)

# v0.3.0 Core

This is a ~~smaller~~ less headline-feature-rich release, fixing several bugs, increasing performance, and adding small features necessary for a *solid* web server.

The name comes from the current plan to move core stuff into it's own crate.

## To do

- [x] Full doc coverage (this took *way* too long...)
- [ ] Partial test coverage
- [x] Extension macros
- [x] Additional server-side cache options, including parsing `cache-control` header
- [ ] Cache handling of Vary header (definitely the hardest)
- [x] Byte ranges
- [ ] `read_to_bytes()` performance
- [x] Implement an easy-to-configure proxy extension in kvarn_extensions
- [ ] If-Modified-Since header to increase client cache performance
- [ ] Move core stuff
- [ ] Smart push with id (so all other data isn't pushed on every request)
- [x] Graceful shutdown and handover. Maintenance and updates are now a non-issue!
- [ ] IPv6

# v0.4.0 WebSockets & Auth

This release should contain good WebSocket integration and an easy-to-use Auth API
for quickly adding secure and *extremely speedy* authentication.

## To do

- [ ] WebSocket integration
- [ ] Authentication API in Layer 6

# v0.5.0 HTTP/3

This is where Kvarn becomes cutting-edge.

> Kvarn already has a good flexible design, so adding this is largely making
> a glue-crate to make HTTP/3 accessible like it is in the `h2` crate.

## To do

*Well...*

- [ ] HTTP/3 crate
- [ ] HTTP/3 support in Kvarn
- [ ] cfg to disable new feature

# v0.6.0 DynLan

This is where ***dyn***amic ***lan***guages are introduced to Kvarn. I currently plan on integrating `Wren` and `Lua` to `kvarn_extensions`,
because `Wren` seems very fast and interesting, while `Lua` is simply a classic, with JIT support in Rust.

Also, I'll maybe crate bindings for the Zend engine (PHP) and make a PHP crate. It would allow to run the PHP interpreter
from within Kvarn, possibly improving performance.

## To do

- [ ] Make a good API in `kvarn_extensions` to add dynamic languages
    > Callbacks to Rust function like getting the cache
    > (or the contents of a file from the cache) will be the difficult part.
- [ ] Wren
- [ ] Lua
- [ ] cfg
- [ ] PHP bindings
- [ ] PHP crate
- [ ] isolating PHP requests while keeping VM alive.
