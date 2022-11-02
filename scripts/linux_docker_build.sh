#!/bin/bash

OS=$(uname -o)

echo -e "\n 🏗️  Running Node v'$NODE_VERSION' build for '$OS'"
set -e

export PATH=$PATH:~/.cargo/bin

# check for MUSL Linux (non-GNU)
if [ "$OS" = "Linux" ]; then
  CARGO_NET_GIT_FETCH_WITH_CLI=true
  RUSTFLAGS="-C target-feature=-crt-static"
  export RUSTFLAGS
else # GNU Linux
  CARGO_NET_GIT_FETCH_WITH_CLI=false
fi

export CARGO_NET_GIT_FETCH_WITH_CLI

# build Neon binary for current architecture
echo -e "\n ⚒️  Building package\n"

/usr/local/bin/yarn build
