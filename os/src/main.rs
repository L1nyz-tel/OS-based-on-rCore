#![no_std]
#![no_main]
#![feature(panic_info_message)]
#[macro_use]
mod console;
mod panic;
mod sbi;

use core::{arch::global_asm};
global_asm!(include_str!("entry.asm"));

/// Rust 的入口函数
#[no_mangle]
pub extern "C" fn rust_main() -> ! {
    println!("Hello rCore-Tutorial!");
    panic!("end of rust_main")
}