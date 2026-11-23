# Contributing to mvfstr

## Development process

mvfstr is developed in Meta's internal repository and exported to the
`mvfstr/` directory of [meta/mvfst](https://github.com/meta/mvfst). A pull
request is reviewed here, then imported into the internal repository, where
it goes through internal review and CI before it lands. The change then
appears here with you as its author.

## Pull requests

1. Fork the repository and branch from `main`. Keep a pull request for mvfstr
   to files under `mvfstr/`.
2. Add tests for new behaviour, and update the docs when you change an API.
3. Run these checks from the `mvfstr/` directory:

   ```sh
   cargo build --workspace --all-targets
   cargo test --workspace
   cargo test --workspace --no-default-features --features ring
   cargo clippy --workspace --all-targets --all-features
   cargo doc --workspace --no-deps
   ```

4. Format with `cargo fmt`.
5. If you have not already, complete the Contributor License Agreement.

## Contributor License Agreement ("CLA")

We need a signed CLA before we can accept your pull request. You only need to
sign it once for any of Meta's open source projects:
<https://code.facebook.com/cla>

## Issues

We use [GitHub issues](https://github.com/meta/mvfst/issues) to track public
bugs. Start the title of an mvfstr issue with "mvfstr:", and include the
mvfstr commit, your kernel version, your Rust version, and steps to reproduce
the problem.

Do not file a public issue for a security bug. See
[SECURITY.md](https://github.com/meta/mvfst/blob/main/mvfstr/SECURITY.md).

## License

By contributing to mvfstr, you agree that your contributions will be licensed
under the [MIT license](https://github.com/meta/mvfst/blob/main/mvfstr/LICENSE).
