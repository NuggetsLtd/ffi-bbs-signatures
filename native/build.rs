extern crate cbindgen;
extern crate neon_build;

use std::env;

fn main() {
  // set feature flags for build
  if let Ok(feature) = env::var("CARGO_CFG_FEATURE") {
    println!("cargo:rustc-cfg=feature=\"{}\"", feature);

    match feature.as_str() {
      "java" => (),
      "c" => {
        // generate C header
        if let Ok(crate_dir) = env::var("CARGO_CFG_MANIFEST_DIR") {
          cbindgen::Builder::new()
            .with_crate(crate_dir)
            .with_language(cbindgen::Language::C)
            .generate()
            .expect("Unable to generate bindings")
            .write_to_file("../wrappers/c/libbbs.h");
        }
      },
      "node" => {
        neon_build::setup(); // must be called in build.rs
      },
      _ => ()
    }
  }

  // set build for target OS
  if let Ok(target_os) = env::var("CARGO_CFG_TARGET_OS") {
    println!("cargo:rustc-cfg=target_os=\"{}\"", target_os);
  }

  // rebuild if any of these env vars have changed
  println!("cargo:rerun-if-env-changed=CARGO_CFG_FEATURE");
  println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_OS");
  println!("cargo:rerun-if-env-changed=CARGO_CFG_MANIFEST_DIR");
}
