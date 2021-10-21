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

This is a _real_ performance uplift. It's essentially a complete rewrite of Kvarn.
The pages at kvarn.org, especially the one about [extensions](https://kvarn.org/extensions/) and
the [request pipeline](https://kvarn.org/pipeline.) should make the design choices more clear.
It should be understandable even for non-programmers. It should make it easier to integrate with Kvarn.

> One other big thing is HTTP/2 Push, which makes loading web sites more than 2 times faster.
> Without doing anything from your part, you can expect automatic push to work, resulting in the
> described benefits. Soon, Smart Push will be part of Kvarn, further increasing performance.

## Left to do

-   [x] Tokio
-   [x] Async io
-   [x] Async extensions
-   [x] Flexible interface for HTTP versions
-   [x] HTTP/2
-   [x] limiting
-   [x] HEAD
-   [x] check routing and extensions.md plan
-   [x] more #[inline]
-   [x] Referrer header in `Extensions::new()`
-   [x] cfg (https, multithreading, http2)

# v0.3.0 Core

This is a ~~smaller~~ less headline-feature-rich release, fixing several bugs, increasing performance, and adding small features necessary for a _solid_ web server.

The name comes from the current plan to move core stuff into it's own crate.

## To do

-   [x] Full doc coverage (this took _way_ too long...)
-   [x] Partial test coverage
-   [x] Extension macros
-   [x] Additional server-side cache options, including parsing `cache-control` header
-   [x] Cache handling of Vary header (definitely the hardest)
-   [x] Byte ranges
-   [x] `read_to_bytes()` performance
-   [x] Implement an easy-to-configure proxy extension in kvarn_extensions
-   [x] If-Modified-Since header to increase client cache performance
-   [x] Move core stuff
-   [x] Smart push (so all other data isn't pushed on every request)
-   [x] Graceful shutdown and handover. Maintenance and updates are now a non-issue!
-   [x] IPv6
-   [x] CI
-   [ ] CD

# v0.4.0 WebSockets & Auth

This release should contain good WebSocket integration and an easy-to-use Auth API
for quickly adding secure and _extremely speedy_ authentication.

## To do

-   [ ] WebSocket integration
-   [ ] Authentication API in Layer 6

# v0.5.0 HTTP/3

This is where Kvarn becomes cutting-edge.

> Kvarn already has a good flexible design, so adding this is largely making
> a glue-crate to make HTTP/3 accessible like HTTP/2 is in the `h2` crate.

## To do

_Well..._

-   [ ] HTTP/3 crate
-   [ ] HTTP/3 support in Kvarn
-   [ ] cfg to disable new feature

# v0.6.0 DynLan

This is where **_dyn_**amic **_lan_**guages are introduced to Kvarn. I currently plan on integrating `Wren` and `Lua` to `kvarn_extensions`,
because `Wren` seems very fast and interesting, while `Lua` is simply a classic, with JIT support in Rust.

Also, I'll maybe crate bindings for the Zend engine (PHP) and make a PHP crate. It would allow to run the PHP interpreter
from within Kvarn, possibly improving performance.

Another challenge is isolating requests while using one VM.

## To do

-   [ ] Make a good API in `kvarn_extensions` to add dynamic languages
    > Callbacks to Rust function like getting the cache
    > (or the contents of a file from the cache) will be the difficult part.
-   [ ] Wren
-   [ ] Lua
-   [ ] [Gluon?](https://github.com/gluon-lang/gluon)
-   [ ] cfg
-   [ ] PHP bindings
-   [ ] PHP crate
