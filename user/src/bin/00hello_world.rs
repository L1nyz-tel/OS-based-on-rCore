#![no_std]
#![no_main]

#[macro_use]
extern crate user_lib;

#[no_mangle]
fn main() -> i32 {
    println!("\x1b[32mhello world\x1b[0m");
    print!("    \x1b[38;5;196mprinted by 00helloworld.rs\x1b[0m");
    0
}