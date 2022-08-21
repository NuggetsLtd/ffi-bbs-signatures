set -e

PLATFORM=$1
OUTPUT_LOCATION=./out
LIB_NAME=jose
ANDROID_API_LEVEL=21
MANIFEST_PATH=native/Cargo.toml

if [ -z "$PLATFORM" ]
then
  echo "❌  ERROR: PLATFORM argument must be supplied and must be one of the following: WINDOWS, LINUX, MACOS, IOS, ANDROID"
  exit 1
fi

if [ ! -d "$ANDROID_NDK_HOME" ]
then
  ANDROID_NDK_HOME=$NDK_HOME
fi

echo "🏗️   Building for PLATFORM: $PLATFORM"
echo "➡️   To OUTPUT_LOCATION: $OUTPUT_LOCATION"

case $PLATFORM in
  NODE)
      # Create the root directory for the NodeJS release binaries
      mkdir -p $OUTPUT_LOCATION/node

      # NodeJS build
      echo "💻  Building for NodeJS"
      CARGO_CFG_FEATURE='node' neon build --release
      cp ./native/index.node $OUTPUT_LOCATION/node/
    ;;
  IOS)
      # Create the directories at the output location for the release binaries
      mkdir -p $OUTPUT_LOCATION/ios/x86_64
      mkdir -p $OUTPUT_LOCATION/ios/aarch64
      mkdir -p $OUTPUT_LOCATION/ios/universal

      # Install cargo-lipo
      # see https://github.com/TimNN/cargo-lipo
      cargo install cargo-lipo
      rustup target install x86_64-apple-ios aarch64-apple-ios
      CARGO_CFG_TARGET_OS='ios' CARGO_CFG_FEATURE='c' CARGO_CFG_MANIFEST_DIR='.' cargo lipo --manifest-path $MANIFEST_PATH --release --no-default-features --features c
      cp "./native/target/x86_64-apple-ios/release/lib$LIB_NAME.a" $OUTPUT_LOCATION/ios/x86_64
      cp "./native/target/aarch64-apple-ios/release/lib$LIB_NAME.a" $OUTPUT_LOCATION/ios/aarch64
      cp "./native/target/universal/release/lib$LIB_NAME.a" $OUTPUT_LOCATION/ios/universal
      cp "./wrappers/c/lib$LIB_NAME.h" $OUTPUT_LOCATION/ios
    ;;
  ANDROID)
      if [ ! -d "$ANDROID_NDK_HOME" ]
      then
        echo "❌  ERROR: ANDROID_NDK_HOME argument must be supplied and be a valid directory pointing to the installation of android ndk"
        exit 1
      fi
        mkdir -p $OUTPUT_LOCATION/android

        # ARM build
        echo "🤖  Building for Android"
        rustup target add \
            armv7-linux-androideabi \
            arm-linux-androideabi \
            aarch64-linux-android \
            i686-linux-android \
            x86_64-linux-android

        cd native # `--manifest-path` currently not working for `cargo-ndk`
        CARGO_CFG_TARGET_OS='android' CARGO_CFG_FEATURE='java' cargo ndk \
            -t armeabi-v7a \
            -t arm64-v8a \
            -t x86 \
            -t x86_64 \
            -o ../out/android \
            build --release --no-default-features --features java
      ;;
  *)
    echo "❌  ERROR: PLATFORM unknown: $1"
    exit 1
    ;;
esac
