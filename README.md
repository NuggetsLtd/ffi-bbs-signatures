[![Nuggets](./docs/assets/nuggets-logo.svg)](https://github.com/NuggetsLtd)

# Node BBS+ Signatures FFI (Foreign Function Interface)

![npm-version](https://badgen.net/npm/v/@nuggetslife/ffi-bbs-signatures)
![npm-unstable-version](https://badgen.net/npm/v/@nuggetslife/ffi-bbs-signatures/unstable)
![Master](https://github.com/NuggetsLtd/ffi-bbs-signatures/workflows/push-master/badge.svg)
![Release](https://github.com/NuggetsLtd/ffi-bbs-signatures/workflows/push-release/badge.svg)
![codecov](https://codecov.io/gh/NuggetsLtd/ffi-bbs-signatures/branch/master/graph/badge.svg)

Interface for Rust BBS+ Signatures crate functions, for exposure in various JavaScript environments (i.e. NodeJS, React Native).

## Getting started

To use this package within your project simply run:

**npm**

```
npm install @nuggetslife/ffi-bbs-signatures
```

**yarn**

```
yarn add @nuggetslife/ffi-bbs-signatures
```

## Usage

<!-- See the [sample](./sample) directory for a runnable demo. -->

**Key generation:**

```typescript
import { generateBls12381G1KeyPair } from "@nuggetslife/ffi-bbs-signatures";

// Generate BLS key pair
const blsKeyPair = await generateBls12381G2KeyPair();
```

## Getting started as a contributor

The following describes how to get started as a contributor to this project

### Prerequisites

The following is a list of dependencies you must install to build and contribute to this project

- [Yarn](https://yarnpkg.com/)
- [Rust](https://www.rust-lang.org/)

For more details see our [contribution guidelines](./docs/CONTRIBUTING.md)

#### Install

To install the package dependencies run:

```
yarn install --frozen-lockfile
```

#### Build

To build the project run:

```
yarn build
```

#### Test

To run the test in the project run:

```
yarn test
```

#### Benchmark

To benchmark the implementation locally run:

```
yarn benchmark
```

## Dependencies

This library uses the [josekit](https://crates.io/crates/josekit) rust crate for the implementation of JOSE, which is
then wrapped and exposed in javascript/typescript using [neon-bindings](https://github.com/neon-bindings/neon).

## Security Policy

Please see our [security policy](./SECURITY.md) for additional details about responsible disclosure of security related
issues.

---

<p align="center"><a href="https://nuggets.life" target="_blank"><img height="40px" src ="./docs/assets/nuggets-logo.svg"></a></p><p align="center">Copyright © Nuggets Limited. <a href="./LICENSE">Some rights reserved.</a></p>
