fn main() {
    println!("cargo:rerun-if-changed=native/ndpi_shim.c");
    let lib = pkg_config::Config::new()
        .probe("libndpi")
        .expect("libndpi not found; install nDPI 6.x (brew install ndpi / build from source) and pkg-config");
    let mut build = cc::Build::new();
    build.file("native/ndpi_shim.c");
    for inc in &lib.include_paths {
        build.include(inc);
    }
    build.compile("ndpi_shim");
}
