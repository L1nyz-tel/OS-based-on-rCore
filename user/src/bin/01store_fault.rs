#![no_std]
#![no_main]

#[macro_use]
extern crate user_lib;

#[no_mangle]
fn main() -> i32 {
    println!("\x1b[32mInto Test store_fault, we wiil insert an invalid store opertation\x1b[0m");
    println!("\x1b[38;5;196mKernel should kill this application!\x1b[0m");
    unsafe {
        core::ptr::null_mut::<u8>().write_volatile(0);
    }
    0
}