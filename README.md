<img align="right" width="25%" src="https://kvarn.org/logo.svg">

# Kvarn

> An extensible and efficient forwards thinking web server.

See the [roadmap](roadmap.md) or visit [kvarn.org](https://kvarn.org/)

Kvarn is a modular web server, designed from the ground up without excessive dependencies.
It supports several types of [extensions](https://kvarn.org/extensions/) to make it your own.

The path of requests are documented in the [pipeline](https://kvarn.org/pipeline.) web page which should make integration easier.

# Current state

> Kvarn is under rapid development, so small breaking changes happens.
> v0.3.0 will bring a relatively stable API.

Kvarn ism at the time of writing, very bare-bones. I want to keep it this way, to try to make it as fast as possible.
This, [at least for now](https://kvarn.org/config.), means you'll have to configure it at compile-time
(e.g. add extensions from [`kvarn_extensions`](kvarn_extensions/README.md) and configuring hosts).

v0.2.0 will have two major dependencies; Rustls and Tokio.

I use Rustls to handle encryption; the community can manage security better than one person.
The second, Tokio, is to provide a blazing fast asynchronous runtime, which will make authoring extensions a lot easier.

# Contributing

This library, and all other sub-projects, are distributed under the Apache License 2.0.
So must all contributions also be.

Images and logos are under my copyright unless explicitly stated otherwise.
