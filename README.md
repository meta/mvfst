![alt text](logo.png "MVFST")

[![Linux Build Status](https://github.com/facebook/mvfst/actions/workflows/getdeps_linux.yml/badge.svg)](https://github.com/facebook/mvfst/actions/workflows/getdeps_linux.yml)
[![macOS Build Status](https://github.com/facebook/mvfst/actions/workflows/getdeps_mac.yml/badge.svg)](https://github.com/facebook/mvfst/actions/workflows/getdeps_mac.yml)
[![Windows Build Status](https://github.com/facebook/mvfst/actions/workflows/getdeps_windows.yml/badge.svg)](https://github.com/facebook/mvfst/actions/workflows/getdeps_windows.yml)

## Introduction
`mvfst` (Pronounced *move fast*) is a client and server implementation of [IETF QUIC](https://quicwg.org/) protocol in C++ by Facebook. QUIC is a UDP based reliable, multiplexed transport protocol that will become an internet standard. The goal of `mvfst` is to build a performant implementation of the QUIC transport protocol that applications could adapt for use cases on both the internet and the data-center. `mvfst` has been tested at scale on android, iOS apps, as well as servers and has several features to support large scale deployments.

## Features
**Server features**:
- Multi-threaded UDP socket server with a thread local architecture to be able to scale to multi-core servers
- Customizable Connection-Id routing. The default Connection-Id routing implementation integrates seamlessly with [katran](https://github.com/facebookincubator/katran)
- APIs to enable zero-downtime restarts of servers, so that applications do not have to drop connections when restarting.
- APIs to expose transport and server statistics for debuggability
- Zero-Rtt connection establishment and customizable zero rtt path validation
- Support for UDP Generic segmentation offloading (GSO) for faster UDP writes.

**Client features**:
- Native happy eyeballs support between ipv4 and ipv6 so that applications do not need to implement it themselves
- Pluggable congestion control and support for turning off congestion control to plug in application specific control algorithms

## Source Layout
- `quic/api`:         Defines API that applications can use to interact with the QUIC transport layer.
- `quic/client`:      Client transport implementation
- `quic/codec`:       Read and write codec implementation for the protocol
- `quic/common`:      Implementation of common utility functions
- `quic/congestion_control`: Implementation of different congestion control algorithms such as Cubic and Copa
- `quic/flowcontrol`: Implementations of flow control functions
- `quic/handshake`:   Implementations cryptographic handshake layer
- `quic/happyeyeballs`: Implementation of mechanism to race IPV4 and IPV6 connection and pick a winner
- `quic/logging`:     Implementation of logging framework
- `quic/loss`:        Implementations of different loss recovery algorithms
- `quic/samples`:     Example client and server
- `quic/server`:      Server transport implementation
- `quic/state`:       Defines and implements both connection and stream level state artifacts and state machines


## Dependencies

`mvfst` largely depends on two libraries: [folly](https://www.github.com/facebook/folly) and [fizz](https://www.github.com/facebookincubator/fizz).

## Building mvfst

### Method 1 \[Recommended]: Using Getdeps.py

This script is used by many of Meta's OSS tools.  It will download and build all of the necessary dependencies first, and will then invoke cmake, etc. to build mvfst.  This will help ensure that you build with relevant versions of all of the dependent libraries, taking into account what versions are installed locally on your system.

It's written in python so you'll need python3.6 or later on your PATH.  It works on Linux, macOS and Windows.

The settings for mvfst's cmake build are held in its getdeps manifest `build/fbcode_builder/manifests/mvfst`, which you can edit locally if desired.

#### Dependencies

#### Windows

The Windows build requires Python 3, Git, and the Visual Studio 2022 C++
Build Tools workload with a Windows SDK installed. After cloning the
repository, configure Git from the repository directory so dependency patch
files and long paths are handled consistently:

    git config core.longpaths true
    git config core.autocrlf false

The recommended Windows build uses `getdeps.py` directly. An absolute install
prefix avoids resolving `_build` relative to the dependency scratch directory:

    $installPrefix = Join-Path (Get-Location) "_build"
    python .\build\fbcode_builder\getdeps.py build --build-type RelWithDebInfo --src-dir=. mvfst "--install-prefix=$installPrefix"

If on Linux or MacOS (with homebrew installed) you can install system dependencies to save building them:

    # Clone the repo
    git clone https://github.com/facebook/mvfst.git
    # Install dependencies
    cd mvfst
    sudo ./build/fbcode_builder/getdeps.py install-system-deps --recursive --install-prefix=$(pwd)/_build mvfst


If you'd like to see the packages before installing them:

    ./build/fbcode_builder/getdeps.py install-system-deps --dry-run --recursive mvfst

On other platforms or if on Linux and without system dependencies `getdeps.py` will mostly download and build them for you during the build step.

#### Build

For a simplified build, you can use the `getdeps.sh` wrapper script. This will download and build all the required dependencies, then build mvfst. It will use the default scratch path for building and install the result in _build.

    # Clone the repo
    git clone https://github.com/facebook/mvfst.git
    # Build using the wrapper script
    cd mvfst
    ./getdeps.sh

At the end of the build, mvfst binaries will be installed at `_build/mvfst`. You can find the scratch path from the logs or by running `python3 ./build/fbcode_builder/getdeps.py show-build-dir mvfst`.

For more control over `getdeps.py`, you can run the tool directly.

    # Show help
    python3 ./build/fbcode_builder/getdeps.py build mvfst -h
    # Build mvfst, using system packages for dependencies if available
    python3 ./build/fbcode_builder/getdeps.py --allow-system-packages build mvfst --install-prefix=$(pwd)/_build

#### Run tests

By default `getdeps.py` will build the tests for mvfst. You can use it to run them too:

    python3 ./build/fbcode_builder/getdeps.py test mvfst --install-prefix=$(pwd)/_build

### Method 2 \[Deprecated]: Using build.sh script

This method can be used on Ubuntu 18+ and macOS.

To begin, you should install the dependencies we need for build. This largely
consists of dependencies from [folly](https://github.com/facebook/folly) as well as
[fizz](https://github.com/facebookincubator/fizz).

```
sudo apt-get install         \
    g++                      \
    cmake                    \
    libboost-all-dev         \
    libevent-dev             \
    libdouble-conversion-dev \
    libgoogle-glog-dev       \
    libgflags-dev            \
    libiberty-dev            \
    liblz4-dev               \
    liblzma-dev              \
    libsnappy-dev            \
    make                     \
    zlib1g-dev               \
    binutils-dev             \
    libjemalloc-dev          \
    libssl-dev               \
    pkg-config               \
    libsodium-dev
```

Then, build and install folly and fizz

Alternatively, run the helper script `build_helper.sh` in this subdirectory.
It will install and link the required dependencies and also build folly and fizz.
This may take several minutes the first time.

```
./build_helper.sh
```

After building, the directory `_build/` will contain the dependencies
(under `_build/deps`) whereas `_build/build` will contain all the
built libraries and binaries for `mvfst`.

You can also install `mvfst` as well as its dependencies `folly` and `fizz`
to a custom directory using the build script, by supplying an `INSTALL_PREFIX`
env var.
```
./build_helper.sh -i /usr/local
```
See `./build_helper.sh --help` for more options

You might need to run the script as root to install to certain directories.

By default the build script `build_helper.sh` enables the building of test target (i.e. runs with `-DBUILD_TEST=ON` option). Since some of tests in `mvfst` require some test artifacts of Fizz, it is necessary to supply the path of the Fizz src directory (via option `DFIZZ_PROJECT`) to correctly build all test targets in `mvfst`.

## Run a sample client and server
Building the test targets of `mvfst` should automatically build the sample client and server binaries into the build directory.

For `getdeps.py` build, you can find the echo binary at:
```
cd $(python3 ./build/fbcode_builder/getdeps.py show-build-dir mvfst)/quic/samples/echo
```

For the deprecated `build.sh` script, it will be at the following location if you used the default build path.
```
cd ./_build/build/quic/samples/echo
```

The server will automatically bind to `::1` by default if no host is used, but you can then spin a simple echo server by running:
```
./echo -mode=server -host=<host> -port=<port>
```
and to run a client:
```
./echo -mode=client -host=<host> -port=<port>
```

On Windows, run the executable from PowerShell with the same options:

```powershell
.\echo.exe -mode=server -host=127.0.0.1 -port=4433
.\echo.exe -mode=client -host=127.0.0.1 -port=4433
```

For more options, see
```
./echo --help
```
## HTTP/3
This repo implements the QUIC transport. For an HTTP/3 implementation that uses Mvfst, please check out [Proxygen](https://github.com/facebook/proxygen).

## Contributing

We'd love to have your help in making `mvfst` better. If you're interested, please
read our guide to [guide to contributing](CONTRIBUTING.md)

Please feel free to
[open an issue](https://github.com/facebook/mvfst/issues) to ask questions or start discussions.

## License
`mvfst` is MIT licensed, as found in the LICENSE file.

## API
The API should be considered in alpha. We can't predict all the use cases that
people will have, so we're waiting some time before declaring a more stable API.
We are open to have several different APIs for different constraints.

## Reporting and Fixing Security Issues

Please do not open GitHub issues or pull requests - this makes the problem
immediately visible to everyone, including malicious actors. Security issues in
`mvfst` can be safely reported via Facebook's Whitehat Bug Bounty program:

https://www.facebook.com/whitehat

Facebook's security team will triage your report and determine whether or not is
it eligible for a bounty under our program.
