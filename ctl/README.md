# [kvarnctl](https://kvarn.org/ctl/)

> Communication with Kvarn from the command line.

kvarnctl takes a command from you and sends it to Kvarn.

The Kvarn instance listening for commands may implement arbetrary commands through the [plugin interface](https://doc.kvarn.org/kvarn/struct.RunConfig.html#method.add_plugin).

See [the CI on GitHub](https://github.com/Icelk/kvarn/actions/workflows/kvarnctl.yml) for Linux downloads.

## Custom ctl path

If you [configured Kvarn to listen to a custom path](https://doc.kvarn.org/kvarn/struct.RunConfig.html#method.set_ctl_path),
you can specify it using the `-p` flag. If the path is relative, its base is `/tmp/`.

## Common commands

-   `kvarnctl shutdown` - this gracefully shuts Kvarn down (if the Kvarn feature `graceful-shutdown` is enabled)
-   `kvarnctl reload` - [handover](https://kvarn.org/shutdown-handover.) to the new binary, located on the same path as the current was started on.
-   `kvarnctl ping <message>` - test if the Kvarn instance is responsive. It will return `<message>` and print it to the terminal.

## Platform support

This isn't supported on Windows as it relies on UNIX socket.
It's unfeasible we get this working on Windows, as handover isn't possible and the need for remote management on Windows is a very slim market. PRs to `kvarn-socket` with named pipe support is however welcome :)
