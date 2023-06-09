use crate::{sync::UPSafeCell, trap::TrapContext};
use core::arch::asm;
use lazy_static::*;
const MAX_APP_NUM: usize = 16;
const APP_BASE_ADDRESS: usize = 0x80400000;
const APP_SIZE_LIMIT: usize = 0x20000;
const USER_STACK_SIZE: usize = 4096 * 2;
const KERNEL_STACK_SIZE: usize = 4096 * 2;

struct AppManager {
    num_app: usize,
    currrent_app: usize,
    app_start: [usize; MAX_APP_NUM + 1],
}
lazy_static! {
    static ref APP_MANAGER: UPSafeCell<AppManager> = unsafe {
        UPSafeCell::new({
            extern "C" {
                fn _num_app();
            }
            let num_app_ptr = _num_app as usize as *const usize;
            let num_app = num_app_ptr.read_volatile();
            let mut app_start: [usize; MAX_APP_NUM + 1] = [0; MAX_APP_NUM + 1];
            let app_start_raw: &[usize] =
                core::slice::from_raw_parts(num_app_ptr.add(1), num_app + 1);
            app_start[..=num_app].copy_from_slice(app_start_raw);
            AppManager {
                num_app,
                currrent_app: 0,
                app_start,
            }
        })
    };
}
impl AppManager {
    pub fn print_app_info(&self) {
        println!(
            "\x1b[38;5;45m[kernel] Number of apps:\x1b[0m \x1b[38;5;196m{}\x1b[0m",
            self.num_app
        );
        println!(
            "\x1b[38;5;45m[kernel] Current app:\x1b[0m \x1b[38;5;196m{}\x1b[0m",
            self.currrent_app
        );
        println!("\x1b[38;5;45m[kernel] App start addresses: ");
        for i in 0..self.num_app {
            println!(
                "\x1b[38;5;45mApp {}:\x1b[0m \x1b[38;5;196m{:#x}\x1b[0m",
                i, self.app_start[i]
            );
        }
    }
    pub fn get_current_app(&self) -> usize {
        self.currrent_app
    }
    pub fn move_to_next_app(&mut self) {
        self.currrent_app = self.currrent_app + 1;
    }
    unsafe fn load_app(&self, idx: usize) {
        if idx >= self.num_app {
            panic!("Invalid app index");
            // use crate::board::QEMUExit;
            // crate::board::QEMU_EXIT_HANDLE.exit_success();
        }

        println!("[kernel] Loading app_{}", idx);

        unsafe {
            core::slice::from_raw_parts_mut(APP_BASE_ADDRESS as *mut u8, APP_SIZE_LIMIT).fill(0);
        }
        let start = self.app_start[idx];
        let end = self.app_start[idx + 1];

        // load the application code into memory
        let app_code = unsafe { core::slice::from_raw_parts(start as *const u8, end - start) };

        let app_dst =
            unsafe { core::slice::from_raw_parts_mut(APP_BASE_ADDRESS as *mut u8, app_code.len()) };
        app_dst.copy_from_slice(app_code);

        // memory fence about fetching the instruction memory
        asm!("fence.i");
    }
}

pub fn init() {
    print_app_info();
}

pub fn print_app_info() {
    APP_MANAGER.exclusive_access().print_app_info();
}

pub fn run_next_app() -> ! {
    let mut app_manager = APP_MANAGER.exclusive_access(); // 获取独占访问
    let current_app = app_manager.get_current_app();
    unsafe {
        app_manager.load_app(current_app);
    }
    app_manager.move_to_next_app();

    drop(app_manager); // explicitly drops the exclusive access to the APP_MANAGER, allowing other parts of the code to access and modify it again.

    extern "C" {
        fn __restore(cx_addr: usize);
    }
    unsafe {
        __restore(KERNEL_STACK.push_context(TrapContext::app_init_context(
            APP_BASE_ADDRESS,
            USER_STACK.get_sp(),
        )) as *const _ as usize);
    }
    panic!("Unreachable in batch::run_current_app!");
}

#[repr(align(4096))]
struct KernelStack {
    data: [u8; KERNEL_STACK_SIZE],
}
#[repr(align(4096))]
struct UserStack {
    data: [u8; USER_STACK_SIZE],
}
static KERNEL_STACK: KernelStack = KernelStack {
    data: [0; KERNEL_STACK_SIZE],
};
static USER_STACK: UserStack = UserStack {
    data: [0; USER_STACK_SIZE],
};
impl UserStack {
    fn get_sp(&self) -> usize {
        self.data.as_ptr() as usize + USER_STACK_SIZE
    }
}
impl KernelStack {
    fn get_sp(&self) -> usize {
        self.data.as_ptr() as usize + USER_STACK_SIZE
    }
    fn push_context(&self, cx: TrapContext) -> &'static mut TrapContext {
        let cx_ptr = (self.get_sp() - core::mem::size_of::<TrapContext>()) as *mut TrapContext;
        unsafe {
            *cx_ptr = cx;
        }

        unsafe { cx_ptr.as_mut().unwrap() }
    }
}
