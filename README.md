# wallabean

![wallabean logo](logo-small.png)

This is a lightweight implementation of the [wallabag](https://wallabag.org/) API built with [redbean](https://redbean.dev/). It provides basic read-it-later functionality with SQLite storage and is fairly compatible with the Wallabag Android app. This project is intended for single user and non-production use cases only. Use at your own risk; little security validation has been done on this as I run it within my tailscale network. Full API support not guaranteed, and no warranty provided. The server will start on port 8080 by default and will run on Windows, MacOS, Linux, FreeBSD, OpenBSD and NetBSD across AMD64 and ARM64 thanks to the awesome [αcτµαlly pδrταblε εxεcµταblε](https://justine.lol/ape.html) technology.

## Build

```bash
./build.sh
```

This downloads redbean-3.0.0.com if needed and packages the Lua code into a single executable.

## Run

```bash
./wallabean.com
```

The server will start on port 8080 by default and listen on any interfaces. To change this, see `./wallabean.com --help`

## REPL Usage

When running in an interactive terminal session, wallabean provides a REPL for administration:

* `help()`: Show help text
* `adduser('username', 'password', 'email', 'name')`: Add users
* `makeadmin('username')`: Make a user admin
* `listusers()`: List all users
* `createclient('username', 'client_name')`: Create API clients
* `setloglevel('DEBUG'|'INFO'|'WARN'|'ERROR'|'FATAL')`: Set log level

Admin users technically have an API to create users, but there's no UI/UX for it, and it's not well tested.

## License

MIT. redbean contains software licensed ISC, MIT, BSD-2, BSD-3, zlib. The transitive closure of legal notices can be found inside the binary structure. The licenses are inside the binary and the upstream redbean projects believes that this satisfactorily automates legal compliance, for the redbean project and anyone who uses it.

## AI notice

Significant parts of this project were generated using AI assistance from Amazon Q Developer and OpenCode with Grok Code Fast 1. The logo was generated using DALL·E 3 and minor edits were made using Krita. Pull requests welcome to change any of these, but honestly, don't bother, and please spend your artistic talents on more useful projects...
