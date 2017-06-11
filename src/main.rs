extern crate crypto;
extern crate rustc_serialize;
extern crate rpassword;
use crypto::scrypt;
use rustc_serialize::base64::{ToBase64, Config, CharacterSet, Newline, STANDARD};
use std::io::{self, Write};


fn main() {
    let params = scrypt::ScryptParams::new(16u8, 8u32, 1u32);
    let mut output: [u8; 64] = [0u8; 64];
    let service = rpassword::prompt_response_stderr("Service: ").unwrap();
    let password = rpassword::prompt_password_stderr("Password: ").unwrap();
    scrypt::scrypt(&service.trim().as_bytes(), &password.trim().as_bytes(), &params, &mut output);
    let result = output
                 .to_base64(STANDARD)
                 .replace("/", "")
                 .replace("+", "")
                 .replace("=", "");
    let (result2, _) = result.split_at(16);

    let stdout = io::stdout();
    let mut handle = stdout.lock();
    handle.write(result2.as_bytes()).unwrap();
}
