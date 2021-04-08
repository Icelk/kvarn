# Roadmap

This is the roadmap for future development of Kvarn.

> The work will be taking place in branches, named after the target release. The order of these feature releases are not set in stone;
> the features of 0.4.0 might come out as version 0.3.0


# v0.1.0

This milestone is reached. It was the first working state of the web server, and is currently running [icelk.dev](https://icelk.dev) and [kvarn.org](https://kvarn.org).

It's slow, not having async IO except for requests; FS is utterly slow and
making any other async requests to a database or to proxy another server does not work
(technically it does, but performance is miserable).


# v0.2.0 Tokio

This is a *real* performance uplift. It's essentially a complete rewrite of Kvarn.
[extensions.md](extensions.md) and [routing.md](routing.md) are documents designed to make the server's
architecture more *transparent*, even for non-programmers. It should make it easier to integrate with Kvarn.

## Left to do

- [x] limiting
- [ ] HEAD
- [ ] check routing and extensions.md plan
- [x] cfg (https, multithreading, http2)


# v0.3.0 Core

This is a smaller release, fixing several bugs, increasing performance, and adding small future necessary for a good web server.

Name comes from the current plan to move core stuff into it's own crate.

## To do

- [ ] Cache handling of Vary header (definitely the hardest)
- [ ] Byte ranges
- [ ] `read_to_bytes()` performance
- [ ] Implement an easy-to-configure proxy extension in kvarn_extensions
- [ ] If-Modified-Since header to increase client cache performance
- [ ] Move core stuff


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

This is where ***dyn***amic ***lan***guages are introduces to Kvarn. I currently plan on integrating `Wren` and `Lua` to `kvarn_extensions`,
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
