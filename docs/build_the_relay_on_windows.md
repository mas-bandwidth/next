# Build the relay on Windows

The relay builds and runs on Windows so you can develop and test Network Next related
code there. It is the userspace-mode relay: the exact same `relay_xdp.c` datapath that
ships as the production XDP program, compiled as a plain Windows console application
with winsock sockets and winhttp backend comms. **It is a dev/test tool only — the
production relay is the XDP relay on Linux** (see `relay/CONSOLIDATION.md`).

## Build on Windows with MSYS2

1. Install [MSYS2](https://www.msys2.org/) and open a **MINGW64** shell.

2. Install the toolchain:

```
pacman -S --needed mingw-w64-x86_64-gcc make wget tar
```

3. Get the prebuilt mingw libsodium and build:

```
cd relay/xdp
wget https://download.libsodium.org/libsodium/releases/old/libsodium-1.0.18-mingw.tar.gz
tar -zxf libsodium-1.0.18-mingw.tar.gz
make userspace-windows WINDOWS_CC=gcc
```

This produces `relay-userspace.exe`.

## Cross compile from Linux or Mac

```
# linux: sudo apt install gcc-mingw-w64-x86-64        mac: brew install mingw-w64
cd relay/xdp
wget https://download.libsodium.org/libsodium/releases/old/libsodium-1.0.18-mingw.tar.gz
tar -zxf libsodium-1.0.18-mingw.tar.gz
make userspace-windows
```

The CI Build pipeline cross compiles the Windows relay and smoke tests the exe under
wine on every tag, so it cannot silently rot.

## Run it

The relay is configured entirely through environment variables, exactly like the
Linux relay. For example, against a local func backend:

```
set RELAY_NAME=relay.1
set RELAY_PUBLIC_ADDRESS=127.0.0.1:2000
set RELAY_BACKEND_URL=http://127.0.0.1:30000
set RELAY_PUBLIC_KEY=1nTj7bQmo8gfIDqG+o//GFsak/g1TRo4hl6XXw1JkyI=
set RELAY_PRIVATE_KEY=cwvK44Pr5aHI3vE3siODS7CUgdPI/l1VwjVZ2FvEyAo=
set RELAY_BACKEND_PUBLIC_KEY=IsjRpWEz9H7qslhWWupW4A9LIpVh+PzWoLleuXL1NUE=
relay-userspace.exe
```

Generate real keypairs with `next keygen`. Ctrl+C stops the relay; Ctrl+Break performs
a clean shutdown (the Windows stand-in for SIGHUP).

The exe is built with `RELAY_TEST=1` and `RELAY_LOGS=1`, so it prints per-packet debug
lines and honors the functional-test environment variables (`RELAY_PRINT_COUNTERS`,
`RELAY_FAKE_PACKET_LOSS_PERCENT`, `RELAY_SHUTDOWN_TIME`, ...).
