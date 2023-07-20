# Roadmap

This is the roadmap for future development of Kvarn.

Info on changes in older versions are available at the [changelog](CHANGELOG.md).

> The work will be taking place in branches, named after the target release. The order of these feature releases are not set in stone;
> the features of 0.7.0 might come out as version 0.6.0

# v0.6.0 edgebleed

This is where Kvarn turns into a cutting-edge web server.

> Kvarn already has a good flexible design, so adding this is largely making
> a glue-crate to make HTTP/3 accessible like HTTP/2 is in the `h2` crate.

## v0.8.0 io_uring

Use Linux's new `io_uring` interface for handling networking and IO on Linux.
This should improve performance and power efficiency. This is merged into v0.6.0.

## To do

_Well..._

-   [x] HTTP/3 support in Kvarn
-   [x] cfg to disable new feature
-   [x] io_uring support
-   [x] io_uring support for HTTP/3

# v0.7.0 DynLan

This is where *dyn*amic *lan*guages are introduced to Kvarn. I currently plan on integrating `Wren` and `Lua` to `kvarn_extensions`,
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
