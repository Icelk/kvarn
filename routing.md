This document will contain all information about how incoming requests are handled in Kvarn.

This is here to make development easier; to have a clear plan of what to do, where to implement it, and the branching of functions.

# Layer 1 / Transport Layer

This is the layer managing the transport layer of the connections. Currently, it's not implemented, but that should be easy (said that before, haven't you?).

This is needed for HTTP/3 with its QUIC protocol. I'll probably use either quinn or quiche

TCP will not get effected.

Converted to stream

# Layer 2 / Encryption

This is where encryption takes place, or not. TLS will be processed here.

Unencrypted HTTP will be passed through.

Request is still a stream

# Layer 3 / HTTP

This is where all HTTP versions (1, 2 and 3) are managed to give a common API.

Here, the compressed headers of HTTP/2 and HTTP/3 are resolved.

Body still stream (at least kinda, see `application.rs#Body` for more info) but headers are parsed

# Layer 4 / Caching and compression

All outgoing data from this layer is cached based on the output of Layer 5.

Rules can be created to get hits from other pages (Prime extension) when accessing a page; server-side redirecting, above the caching level.

Compression can be `None` or `Full` to regulate automatic caching.

Caching has two options:
- Client cache; configurations of the `Content-Encoding` header
- Server cache, `None`, `QueryMatters` (requested path has to match query) or `Full` (query of path is ignored, to prevent DDOS attacks circumventing the *fast* cache)

After the response is created by Layer 5, Present extensions are run here.

Then, each time the response is sent, Package extensions are run.

After the response has been sent, Post extensions are resolved.

# Layer 5.1 / Pathing

This is where the data of `::http::Request` is interpreted to either read a file, run a Prepare extension, call PHP, or any *path*.

*Prepare* extensions are called inside of this function.

## Layer 6 / Lib API

Only meant to be used from Layer 5.1.

This translates header values to more helpful structs, such as `Accept*` and `Authentication`
Can be found using Kvarns public API, through the module `helper`

# Layer 5.2/ Extension: Pre

This whole layer can be customised, to for example implement a proxy. You have complete control over the outgoing data,
but can return a `::http::Response`, cache method, and suggested compression.

You can inject a function to be run, and if you choose, intercept the request.
