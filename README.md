# Kvarn

> An extensible and efficient forwards thinking web server

Kvarn is a modular web server, designed from the ground up without excessive dependencies.
It supports several types of [extensions](extensions.md) to make it your own.
The path of requests are documented in the [routing](routing.md) document which should make integration easier.


# Current state

> Kvarn is under rapid development, so breaking changes will happen (often as a product of redesigning parts of the architecture).
> The next version, 0.2.0 should have a more stable API.

Kvarn is at the time of writing very bare-bones. I want to keep it this way. I'll try to make it as fast as possible, which often means you'll have
to configure it at build time (e.g. add extensions from [`kvarn_extensions`](kvarn_extensions/README.md)).

v0.2.0 will have two major dependencies; Rustls and Tokio.
I use Rustls to handle encryption; the community can manage security better than one person.
The second, Tokio, is to provide a blazing fast asynchronous runtime, which will make authoring extensions a lot easier.


# Contributing

This library, and all other sub-projects, are distributed under the Apache License 2.0

Images and logos are under my copyright unless otherwise explicitly stated.
