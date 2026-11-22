# Contributing to MVFST
Here's a quick rundown of how to contribute to this project.

## Code of Conduct
The code of conduct is described in [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)

## Our Development Process
We develop on a private branch internally at Facebook. We regularly update
this github project with the changes from the internal repo. External pull
requests are cherry-picked into our repo and then pushed back out.

## Pull Requests
We actively welcome your pull requests.

1. Fork the repo and create your branch from `main`.
1. If you've added code that should be tested, add tests
1. If you've changed APIs, update the documentation.
1. Ensure the test suite passes.
1. Run the local validation steps described below.
1. If you haven't already, complete the Contributor License Agreement ("CLA").

## Local Validation

Run the build and test commands from the repository root before opening a pull
request:

```sh
python3 ./build/fbcode_builder/getdeps.py build mvfst --install-prefix="$(pwd)/_build"
python3 ./build/fbcode_builder/getdeps.py test mvfst --install-prefix="$(pwd)/_build"
```

On Windows, use the PowerShell build setup and command documented in the
[README](README.md#building-mvfst). The equivalent commands use `python` and
an absolute install prefix.

For C++ changes, format each modified file with `clang-format` before
committing:

```sh
clang-format -i path/to/changed_file.cpp path/to/changed_file.h
```

## Contributor License Agreement ("CLA")
In order to accept your pull request, we need you to submit a CLA. You
only need
to do this once to work on any of Facebook's open source projects.

Complete your CLA here: <https://code.facebook.com/cla>

## Issues
We use GitHub issues to track public bugs. Please ensure your description
is clear and has sufficient instructions to be able to reproduce the issue.

Facebook has a [bounty program](https://www.facebook.com/whitehat/) for
the safe disclosure of security bugs. In those cases, please go through
the process outlined on that page and do not file a public issue.

## Coding Style
We use clang-format tool for coding style.
Please run it on each C++ file where changes were made before committing.

## License
By contributing to MVFST, you agree that your contributions will be
licensed under its BSD license.
