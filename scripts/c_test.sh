#!/bin/sh

BLUE='\033[1;36m'
GREEN='\033[1;32m'
NC='\033[0m' # No Color

echo ""
echo "${BLUE}----- ⏳ BUILD: C -> RUST FOREIGN FUNCTION INTERFACE ----------------------------------${NC}"
echo ""
CARGO_CFG_TARGET_OS='ios' CARGO_CFG_FEATURE='c' CARGO_CFG_MANIFEST_DIR='.' cargo build --manifest-path native/Cargo.toml --release --no-default-features --features c
echo ""
echo "${GREEN}----- ✅ DONE: C -> RUST FOREIGN FUNCTION INTERFACE ----------------------------------${NC}"
echo ""

echo ""
echo "${BLUE}----- ⏳ COMPILE: C TEST CODE ---------------------------------------------------------${NC}"
echo ""
gcc wrappers/c/main.c -L native/target/release/ -ljose -o wrappers/c/test.out
echo ""
echo "${GREEN}----- ✅ DONE: C TEST CODE -----------------------------------------------------------${NC}"
echo ""

echo ""
echo "${BLUE}----- ⏳ RUN: C TEST CODE -------------------------------------------------------------${NC}"
echo ""
wrappers/c/test.out
echo ""
echo "${GREEN}----- ✅ DONE: C TEST CODE -----------------------------------------------------------${NC}"
echo ""
