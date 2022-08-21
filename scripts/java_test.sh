#!/bin/sh

BLUE='\033[1;36m'
GREEN='\033[1;32m'
NC='\033[0m' # No Color

JAVA_BBS_DIR=wrappers/java/src/main/java/life/nuggets/rs

echo ""
echo "${BLUE}----- ⏳ BUILD: Java -> RUST FOREIGN FUNCTION INTERFACE ----------------------------------${NC}"
echo ""
pwd
CARGO_CFG_TARGET_OS='android' CARGO_CFG_FEATURE='java' cargo build --manifest-path native/Cargo.toml --release --no-default-features --features java
cp native/target/release/libbbs.dylib  wrappers/java/src/main/jniLibs/darwin-x86_64/libbbs.dylib
echo ""
echo "${GREEN}----- ✅ DONE: Java -> RUST FOREIGN FUNCTION INTERFACE ----------------------------------${NC}"
echo ""

echo ""
echo "${BLUE}----- ⏳ BUILD: Java header --------------------------------------------------------------${NC}"
echo ""
pwd
javac -h $JAVA_BBS_DIR $JAVA_BBS_DIR/Bbs.java
echo ""
echo "${GREEN}----- ✅ DONE: Java header --------------------------------------------------------------${NC}"
echo ""

echo ""
echo "${BLUE}----- ⏳ COMPILE: Java -------------------------------------------------------------------${NC}"
echo ""
pwd
javac $JAVA_BBS_DIR/Bbs.java
echo ""
echo "${GREEN}----- ✅ DONE: Java compiled ------------------------------------------------------------${NC}"
echo ""

echo ""
echo "${BLUE}----- ⏳ RUN: JAVA TEST CODE -------------------------------------------------------------${NC}"
echo ""
cd $JAVA_BBS_DIR/../../../
java -cp . -Djava.library.path=../jniLibs/darwin-x86_64/ life.nuggets.rs.Bbs
echo ""
echo "${GREEN}----- ✅ DONE: JAVA TEST CODE -----------------------------------------------------------${NC}"
echo ""
