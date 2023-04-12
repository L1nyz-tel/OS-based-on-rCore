#![no_std]
#![no_main]
#![feature(panic_info_message)]
#[macro_use]
mod console;
pub mod batch;
mod lang_item;
mod sbi;
mod sync;
mod trap;
mod syscall;

use core::arch::global_asm;
global_asm!(include_str!("entry.asm"));
global_asm!(include_str!("link_app.S"));

fn clear_bss() {
    extern "C" {
        fn sbss();
        fn ebss();
    }
    (sbss as usize..ebss as usize).for_each(|a| {
        unsafe { (a as *mut u8).write_volatile(0) }
    });
}

/// Rust 的入口函数
#[no_mangle]
pub extern "C" fn rust_main() -> ! {
    clear_bss();
    println!("Hello rCore-Tutorial!");
    panic!("end of rust_main");
}