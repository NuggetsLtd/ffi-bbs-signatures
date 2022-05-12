# BBS Signatures FFI (Foreign Function Interface)
A package to interface with binary BBS Signatures packages written in Rust, with interfaces for:

- NodeJS
- Android
- iOS

## NodeJS
The NodeJS to Rust interface uses [Neon Bindings](https://neon-bindings.com/) to provide an interface between NodeJS and the Rust binaries. This translates data structures and function calls between both sides.

Install NodeJS packages:
```sh
yarn
```

Build Neon interface to Rust binaries:
```sh
yarn build:neon
```

Run Neon interface tests:
```sh
yarn test:neon
```
