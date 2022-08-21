#!/bin/sh
set -e

echo "➕  Installing Dependencies"

if ! [ -x "$(command -v rustup)" ]; then
    echo "🔧  Installing rustup"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    echo "🦀  Rustup installed"
else
  echo "🦀  Rustup already installed"
fi
