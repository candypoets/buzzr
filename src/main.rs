//! Thin binary wrapper: the whole CLI lives in `buzzr::cli`.

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(buzzr::cli::main(&args));
}
