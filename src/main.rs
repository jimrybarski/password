extern crate crypto;
extern crate rustc_serialize;
extern crate rpassword;
use crypto::scrypt;
use rustc_serialize::base64::{ToBase64, STANDARD};
use std::io::{self, Write};


fn run() -> Result<(), std::io::Error> {
    // ask the user for the site/service and their secret key
    let service = rpassword::prompt_response_stderr("Service: ")?;
    let password = rpassword::prompt_password_stderr("Password: ")?;

    let params = scrypt::ScryptParams::new(16u8, 8u32, 1u32);
    // 64 bytes is way more than necessary but it's what the Python scrypt library defaults to
    // and it guarantees we'll have plenty of characters even after removing non-alphanumerics
    let mut output: [u8; 64] = [0u8; 64];
    // the first argument is technically supposed to be the password, but it doesn't matter. For
    // historical reasons (i.e. my Python implementation got it backwards) the service goes first
    scrypt::scrypt(service.trim().as_bytes(), password.trim().as_bytes(), &params, &mut output);
    let untrimmed_output = output
                           .to_base64(STANDARD)
                           .replace("/", "")
                           .replace("+", "")
                           .replace("=", "");
    // this could panic if we miss a codepoint boundary, but we're guaranteed to have only valid UTF-8, so it never will
    let output = untrimmed_output.split_at(16).0;

    // write the result to stdout. Since this always needs to be pasted into a form or a terminal,
    // I pipe this into xclip, which prevents it from being printed to the screen:
    // password | xclip -i -selection clipboard
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    handle.write_all(output.as_bytes())
}

fn main() {
    match run() {
        Ok(_) => {},
        Err(_) => { std::process::exit(1); }
    }
}
