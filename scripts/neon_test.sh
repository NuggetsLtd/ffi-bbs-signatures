#!/bin/sh

BLUE='\033[1;36m'
GREEN='\033[1;32m'
NC='\033[0m' # No Color

echo ""
echo "${BLUE}----- ⏳ BUILD: NODEJS -> RUST FOREIGN FUNCTION INTERFACE ----------------------------------${NC}"
echo ""
CARGO_CFG_FEATURE='node' neon build --release
echo ""
echo "${GREEN}----- ✅ DONE: NODEJS -> RUST FOREIGN FUNCTION INTERFACE ----------------------------------${NC}"
echo ""

echo ""
echo "${BLUE}----- ⏳ RUN: NEON BINDINGS TEST CODE -------------------------------------------------------------${NC}"
echo ""
jest --config jest.config.neon.json
echo ""
echo "${GREEN}----- ✅ DONE: NEON BINDINGS TEST CODE -----------------------------------------------------------${NC}"
echo ""
