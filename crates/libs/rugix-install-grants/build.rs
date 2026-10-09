fn main() {
    sidex_build_rs::configure()
        .with_bundle(".")
        .generate()
        .expect("failed to generate installation grant types");
}
