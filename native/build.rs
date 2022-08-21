extern crate neon_build;
use std::env;

fn main() {
    neon_build::setup(); // must be called in build.rs

    // set feature flags for build
    if let Ok(feature) = env::var("CARGO_CFG_FEATURE") {
        println!("cargo:rustc-cfg=feature=\"{}\"", feature);
    }
    
    // set build for target OS
    if let Ok(target_os) = env::var("CARGO_CFG_TARGET_OS") {
        println!("cargo:rustc-cfg=target_os=\"{}\"", target_os);
    }
}
