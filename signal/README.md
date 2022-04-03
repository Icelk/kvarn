# kvarn_signal

> A library to send messages to and from Kvarn instances.

`kvarn_signal` provides the backbone of the communications of [`kvarnctl`](https://github.com/Icelk/kvarn/tree/main/ctl/).

It is currently only supported on UNIX, as we use UNIX sockets.
There are plans to use named pipes on Windows. This is however a low priority,
as managing of servers on Windows seems like it would be a seldom used feature.

See [doc.kvarn.org](https://doc.kvarn.org/kvarn_signal/) for the most up-to-date docs.
