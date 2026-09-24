use std::env;

fn main() {
    let sdk = env::var("DEP_IDALIB94_SDK").expect("DEP_IDALIB94_SDK set by idalib-sys");
    println!("cargo:rustc-env=IDALIB_SDK={sdk}");
}
