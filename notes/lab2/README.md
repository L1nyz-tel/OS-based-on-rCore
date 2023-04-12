**批处理系统** (Batch System) 应运而生，它可用来管理无需或仅需少量用户交互即可运行的程序，在资源允许的情况下它可以自动安排程序的执行，这被称为“批处理作业”，这个名词源自二十世纪 60 年代的大型机时代。

操作系统需要能够终止出错的应用程序，转而运行下一个应用程序。这种 _保护_ 计算机系统不受有意或无意出错的程序破坏的机制被称为 **特权级** (Privilege) 机制，它让应用程序运行在用户态，而操作系统运行在内核态，且实现用户态和内核态的隔离

本章主要是设计和实现建立支持批处理系统的操作系统，从而对可支持运行一批应用程序的执行环境有一个全面和深入的理解。

# 特权级机制

操作系统和应用程序之间存在特权级机制的原因是应用程序的安全性不可信赖。

操作系统和应用程序紧密连接在一起，构成一个整体来执行。随着应用需求的增加，操作系统的体积也越来越大；同时应用自身也会越来越复杂。

由于操作系统会被频繁访问，来给多个应用提供服务，所以它可能的错误会比较快地被发现。

但应用自身的错误可能就不会很快发现。

因此，计算机科学家和工程师想到了一个方法：让相对安全可靠的操作系统运行在一个硬件保护的安全执行环境中，而让应用程序运行在另外一个无法破坏操作系统的受限执行环境中。

为确保操作系统的安全，需要限制应用程序访问任意的地址空间和执行某些可能破坏计算机系统的指令。

为了让应用程序获得操作系统的函数服务，可以采用传统的函数调用方式，但这种方式会绕过硬件的特权级保护检查。

因此，可以设计新的机器指令：执行环境调用（ecall）和执行环境返回（eret），它们分别具有用户态到内核态和内核态到用户态的执行环境切换能力。

操作系统需要提供相应的功能代码

- 在执行 eret 前准备和恢复用户态执行应用程序的上下文
- 并在应用程序调用 ecall 指令后检查其系统调用参数，确保参数不会破坏操作系统。

## RISC-V 特权级

| 级别 | 编码 | 名称          |
| ---- | ---- | ------------- |
| 0    | 00   | 用户/应用模式 |
| 1    | 01   | 监督模式      |
| 2    | 10   | 虚拟监督模式  |
| 3    | 11   | 机器模式      |

用户态应用直接触发从用户态到内核态异常的原因

1. 用户态软件为了获得内核态操作系统的服务功能
2. 执行了用户态不允许的指令或其他错误，被 CPU 检测到

RISC-V 特权级规范定义了**可能会导致从低特权级到高特权级的各种异常:**

| Exception Code | Description                    |
| -------------- | ------------------------------ |
| 0              | Instruction address misaligned |
| 1              | Instruction access fault       |
| 2              | Illegal instruction            |
| 3              | Breakpoint                     |
| 4              | Load address misaligned        |
| 5              | Load access fault              |
| 6              | Store/AMO address misaligned   |
| 7              | Store/AMO access fault         |
| 8              | Environment call from U-mode   |
| 9              | Environment call from S-mode   |
| 11             | Environment call from M-mode   |
| 12             | Instruction page fault         |
| 13             | Load page fault                |
| 15             | Store/AMO page fault           |

## RISC-V 特权指令

与特权级无关的一般指令和通用寄存器 `x0 ~ x31` 在任何特权级中都可以运行

每个特权级都对应一些特殊指令和**控制状态寄存器**，来控制该特权级的某些行为并描述其状态

在 RISC-V 中，会有两类属于高特权级 S 模式的特权指令

- 指令本身属于高特权级指令，如 `sret` 指令（表示从 S 模式返回到 U 模式）
- 指令访问了 **S 模式特权级下才能访问的寄存器或内存**，如表示 S 模式系统状态的 **控制状态寄存器 `sstatus`**

|          指令          |                                                                                                   含义                                                                                                   |
| :--------------------: | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------: |
|          sret          |                                                                         从 S 模式返回 U 模式: 在 U 模式下执行会产生非法指令异常                                                                          |
|          wfi           |                                                                 处理器在空闲时进入低功耗状态等待中断: 在 U 模式下执行会产生非法指令异常                                                                  |
|       sfence.vma       |                                                                             刷新 TLB 缓存: 在 U 模式下执行会产生非法指令异常                                                                             |
| 访问 S 模式 CSR 的指令 | 通过访问 [sepc/stvec/scause/sscartch/stval/sstatus/satp 等 CSR](http://rcore-os.cn/rCore-Tutorial-Book-v3/chapter2/4trap-handling.html#term-s-mod-csr) 来改变系统状态：在 U 模式下执行会产生非法指令异常 |

# 实现应用项目

## 应用程序设计

如何设计实现被批处理系统逐个加载并运行的应用程序。前提: 应用程序假定在用户态(U 特权级模式)下运行。

应用程序的设计要点是:

1. 应用程序的内存布局
2. 应用程序发出的系统调用

应用程序、用户库放在项目根目录 `user` 下

- `user/src/bin/*.rs` ：各个应用程序
- `user/src/*.rs` ：用户库（包括入口函数、初始化函数、I/O 函数和系统调用接口等）
- `user/src/linker.ld` ：应用程序的内存布局说明。

### 项目结构

`user/src/bin/` 里面存在多个文件，目前至少有三个文件

- `hello_world`
- `store_fault` 访问一个非法地址，测试批处理系统是否会被错误影响
- `power` 不断在计算操作和打印字符串之间进行特权级交换

在 `user/src/bin/*.rs` 代码中尝试引用外部库:

```rust
#[macro_use]
extern crate user_lib;
```

在 `user/Cargo.toml` 中对库名进行设置 `name = "user_lib"`

在 `user/src/lib.rs` 中定义了用户库的入口点 `_start`:

```rust
#[no_mangle]
#[link_section = ".text.entry"]
pub extern "C" fn _start -> ! {
	clear_bss();
	exit(main());
	panic!("unreachable after sys_exit!");
}

#[linkage = "weak"]
#[no_mangle]
fn main() -> i32 {
    panic!("Cannot find main!");
}
```

- 使用 Rust 的宏将 `_start` 将编译后的汇编代码放在一个名为 `.text.entry` 的代码段中，方便后续链接时调整它的位置，使得它能够作为用户库的入口。
- 进入用户库入口后，手动清空需要零初始化的 `.bss` 段
- 使用 Rust 的宏将 `main` 标志为弱链接。效果是: 在 `lib.rs` 和 `bin` 目录下某个应用程序都有 `main` 符号，但是由于 `lib.rs` 中的 `main` 符号是弱链接，链接器会使用 `bin` 目录下的应用主逻辑作为 `main`
  - 如果 `bin` 中找不到任何 `main`，那编译也能通过

为了支持上述链接操作，需要在 `lib.rs` 开头加入

```rust
#![feature(linkage)]
```

### 内存布局

在 `user/.cargo/config` 中设置链接时使用脚本

- 程序起始物理地址调整为 `0x80400000`，三个应用程序都会被加载到这个物理地址上运行
- 将 `_start` 所在的 `.text.entry` 放在整个程序的开头
- 提供最终生成可执行文件的 `.bss` 段的起始和终止地址，方便 `clear_bss` 函数调用

### 系统调用

在用户态中，`ecall` 指令会触发名为 **Environment call from U-mode** 异常，并 **Trap** **进入 S 模式执行批处理系统针对这个异常特别提供的服务代码**

应用程序和批处理系统之间按照 API 的结构，约定如下两个系统调用:

```rust
/// 功能: 将内存中缓冲区中的数据写入文件
/// 参数：`fd` 表示待写入文件的文件描述符；
///      `buf` 表示内存中缓冲区的起始地址；
///      `len` 表示内存中缓冲区的长度。
/// 返回值：返回成功写入的长度。
fn sys_write(fd: usize, buf: *const u8, len: usize) -> isize;

/// 功能：退出应用程序并将返回值告知批处理系统。
/// 参数：`exit_code` 表示应用程序的返回值。
/// 返回值：该系统调用不应该返回。
/// syscall ID：93
fn sys_exit(exit_code: usize) -> !;
```

RISC-V 调用规范中，**约定寄存器 `a0-a6` 保存系统调用的参数，`a0` 保存系统调用的返回值，`a7`用来传递 syscall ID**

```rust
// user/src/syscall.rs
use core::arch::asm;
fn syscall(id: usize, args: [usize; 3]) -> isize {
    let mut ret: isize;
    unsafe {
        asm!(
            "ecall",
            inlateout("x10") args[0] => ret,
            in("x11") args[1],
            in("x12") args[2],
            in("x17") id
        );
    }
    ret
}
```

第 3 行，将所有的系统调用都封装成 `syscall` 函数

于是 `sys_write` `sys_exit` 只需将 `syscall` 进行包装

```rust
// user/src/syscall.rs
const SYSCALL_WRITE: usize = 64;
const SYSCALL_EXIT: usize = 93;

pub fn sys_write(fd: usize, buffer: &[u8]) -> isize {
    syscall(SYSCALL_WRITE, [fd, buffer.as_ptr() as usize, buffer.len()])
}
pub fn sys_exit(xstate: i32) -> isize {
    syscall(SYSCALL_EXIT, [xstate as usize, 0, 0])
}
```

接下来在用户库 `user_lib` 进一步封装，从而更加接近实际系统调用接口

```rust
// user/src/lib.rs
use syscall::*;

pub fn write(fd: usize, buf: &[u8]) -> isize { sys_write(fd, buf) }
pub fn exit(exit_code: i32) -> isize { sys_exit(exit_code) }
```

## 编译生成应用程序二进制码

1. 对 `src/bin` 下的每个应用程序，在 `target/riscv64gc-unknown-none-elf/release` 目录下生成一个同名的 ELF 可执行文件
2. 使用 objcopy 二进制工具将上一步中生成的 ELF 文件删除所有 ELF header 和符号，得到 `.bin` 后缀的纯二进制镜像文件，之后将被链接进内核

## 实现操作系统前执行应用程序

在 RISC-V 架构中，用户态模拟可使用 `qemu-riscv64` 模拟器，而使用 `qemu-system-riscv64` 模拟器来系统模拟裸机

现在尝试，应用程序执行 S 模式特权指令会出现什么情况

```rust
// user/src/bin/03priv_inst.rs
use core::arch::asm;

#[no_mangle]
fn main() -> i32 {
    println!("try to execute privileged instruction in U Mode");
    println!("Kernel should kill this application!");
    unsafe {
        asm!("sret");
    }
    0
}

// user/src/bin/04priv_csr.rs
use riscv::register::sstatus::{self, SPP};

#[no_mangle]
fn main() -> i32 {
    println!("Try to access privileged CSR in U Mode");
    println!("Kernel should kill this application!");
    unsafe {
        sstatus::set_app(SPP::User);
    }
    0
}
```

测试已有的应用程序

![](https://i.328888.xyz/2023/03/29/iW1DCZ.png)

github 仓库已 public: [https://github.com/linyz-tel/OS-based-on-rCore/tree/84a03571f601b39c7323bf5595ac4d2d6474b718](https://github.com/linyz-tel/OS-based-on-rCore/tree/84a03571f601b39c7323bf5595ac4d2d6474b718)

终端字体色彩参考下表:

![](https://i.328888.xyz/2023/03/30/i0K3Vy.png)

# 实现批处理操作系统

应用放置采用“静态绑定”方式，二操作系统加载应用则采用“动态加载”方式

- 静态绑定: 通过一定的编程技巧，把多个应用程序代码和批处理操作系统代码“绑定”在一起
- 动态加载: 基于静态编码留下的“绑定”信息，操作系统可以找到每个应用程序文件二进制代码的起始地址和长度，并能加载到内存中运行

## 将应用程序链接到内核

将应用程序的二进制镜像文件作为内核的数据段链接到内核中，内核需要知道内含的应用程序的数量和它们的位置，这样才能够在运行时进行管理并加载到物理内存

引入汇编代码 `link_app.S`，这段汇编代码**在构建操作系统时由 `os/build.rs` 自动生成**

```rust
// os/src/main.rs
global_asm!(include_str!("link_app.S"));
```

分析 `link_app.S` 中的内容

- 五个数据段分别插入了五个应用程序的二进制镜像，并各自拥有一对全局符号 `app_*_start, app_*_end` 指示开始和结束的位置
- `_num_app` 开始的数据段，相当于一个 64 位整数数组
  - 数组中第一个元素: 应用程序的数量
  - 后面按照顺序防止每个应用程序的起始地址
  - 最后一个元素放置最后一个应用程序的结束位置

```
# os/src/link_app.S
    .align 3
    .section .data
    .global _num_app

_num_app:
    .quad 5
    .quad app_0_start
    .quad app_1_start
    .quad app_2_start
    .quad app_3_start
    .quad app_4_start
    .quad app_4_end

    .section .data
    .global app_0_start
    .global app_0_end
app_0_start:
    .incbin "../user/target/riscv64gc-unknown-none-elf/release/00hello_world.bin"
app_0_end:

    .section .data
    .global app_1_start
    .global app_1_end
app_1_start:
    .incbin "../user/target/riscv64gc-unknown-none-elf/release/01store_fault.bin"
app_1_end:

    .section .data
    .global app_2_start
    .global app_2_end
app_2_start:
    .incbin "../user/target/riscv64gc-unknown-none-elf/release/02power.bin"
app_2_end:

    .section .data
    .global app_3_start
    .global app_3_end
app_3_start:
    .incbin "../user/target/riscv64gc-unknown-none-elf/release/03priv_inst.bin"
app_3_end:

    .section .data
    .global app_4_start
    .global app_4_end
app_4_start:
    .incbin "../user/target/riscv64gc-unknown-none-elf/release/04priv_csr.bin"
app_4_end:
```

生成 `link_app.S` 的 `os/build.rs` 不是由操作系统内核执行，而是调用了 std 库，并在内核编译之前执行

```rust
// os/build.rs
use std::fs::{read_dir, File};
use std::io::{Result, Write};
use std::process::id;
use std::usize;

static TARGET_PATH: &str = "../user/target/riscv64gc-unknown-none-elf/release/";

fn insert_app_data() -> Result<()> {
    let mut f: File = File::create("src/link_app.S").unwrap();

// scans the `../user/src/bin` directory for files, extracts their names without the file extension, and stores them in a vector called `apps`. This vector will be used later to generate assembly code that includes the binary contents of each application.
    let mut apps: Vec<_> = read_dir("../user/src/bin").unwrap()
        .into_iter()
        .map(|dir_entry|{
            let mut name_with_ext = dir_entry.unwrap().file_name().into_string().unwrap();
            name_with_ext.drain(name_with_ext.find('.').unwrap()..name_with_ext.len());
            name_with_ext
        }).collect();
    apps.sort();

//
    writeln!(
        f,
        r#"
    .align 3
    .section .data
    .global _num_app
_num_app:
    .quad {}"#,
        apps.len()
    )?;

// writes the start and end labels for each application to the file.
    for i in 0..apps.len() {
        writeln!(f, r#"    .quad app_{}_start"#, i)?;
    }
    writeln!(f, r#"    .quad app_{}_end"#, apps.len() - 1)?;

    for (idx, app) in apps.iter().enumerate() {
        println!("app_{}: {}", idx, app);
        writeln!(
            f,
            r#"
    .section .data
    .global app_{0}_start
    .global app_{0}_end
app_{0}_start:
    .incbin "{2}{1}.bin"
app_{0}_end:"#,
            idx, app, TARGET_PATH
        )?;
    }
    Ok(())
}

fn main() {
    println!("catgo:rerun-if-changed=../user/src/");
    println!("catgo:rerun-if-changed={}", TARGET_PATH);
    insert_app_data().unwrap();
}
```

1. `.align 3`: aligns the next instruction on a 8-byte boundary. This means that the next instruction will be located at an address that is a multiple of 8.
2. `.section .data`: specifies that the following instructions will be located in the `.data` section of the program's memory.
3. `?`: is used to propagate any errors that occur during the writing of the string to the caller. If an error occurs, the function will immediately return an `Err` value, otherwise it will return `Ok(())` to indicate that the write operation was successful.
4. `.incbin "{2}{1}.bin"`: directive tells the assembler to include the binary data from the specified file at this point in the program.
5. `catgo:rerun-if-changed=../user/src/`: This is a message to the build system indicating that the build script should be rerun if any file in the `../user/src/` directory changes.

## 找到并加载应用程序二进制码

能够找到并加载应用程序二进制码的应用管理器 `AppManager` 是核心组件

在 `os` 的 `batch` 子模块中实现一个应用管理器，主要功能如下:

- 保存应用数量和各自的位置信息，以及当前执行到第几个应用
- 根据应用程序位置信息，初始化好应用所需内存空间，并加载执行

`AppManager` 结构体定义如下:

```rust
// os/src/batch.rs
struct AppManager {
	num_app: usize,
	current_app: usize,
	app_start: [usize; MAX_APP_NUM + 1],
}
```

由于 AppManager 这一变量需要在程序的任何地方都可以随意的访问它，RefCell 就非常接近我们的需求

- RefCell 具有内部可变性，对不可变的值进行可变借用，参考: [Rust 圣经](https://course.rs/advance/smart-pointer/cell-refcell.html#%E5%86%85%E9%83%A8%E5%8F%AF%E5%8F%98%E6%80%A7)

不过，RefCell 还不足以满足我们的需求，我们需要再封装一个 **标记`Sync` `unsafe` 的 `UPSafeCell`，**允许我们在单核上安全使用可变全局变量\*\*

- [unsafe 特征](https://course.rs/advance/unsafe/superpowers.html#%E5%AE%9E%E7%8E%B0-unsafe-%E7%89%B9%E5%BE%81)
- [sync 特征](https://course.rs/advance/concurrency-with-threads/send-sync.html#send-%E5%92%8C-sync)

```rust
// os/src/sync/up.rs
pub struct UPSafeCell<T> {
    inner: RefCell<T>
}

unsafe impl<T> Sync for UPSafeCell<T> {}

impl<T> UPSafeCell<T> {
    pub unsafe fn new(value: T) -> Self {
        Self{
            inner: RefCell::new(value)
        }
    }

    pub fn exclusive_access(&self) -> RefMut<'_, T> {
        self.inner.borrow_mut()
    }
}
```

- 调用 `exclusive_access` 得到数据的可变借用标记，进而完成数据的读写
- `UPSafeCell` 标记为 `Sync` 使得它可以作为一个全局变量
  - 编译器无法确定 `UPSafeCell` 能否安全的在多线程间共享

之后使用尽量少的 unsafe 来初始化 AppManager 全局实例:

- [lazy_static](https://course.rs/advance/global-variable.html?highlight=lazy_static#lazy_static) 懒初始化静态变量，允许在运行期初始化静态变量
  - `lazy_static` 宏匹配的是 `static ref`，定义的静态变量都是不可变引用

引入 **lazy_static** 需要添加依赖

- `spin_no_std` 是 `lazy_static` 中的一个可选特性，它提供了一个在 `no_std` 环境中工作的 `lazy_static` 版本，其中 Rust 标准库不可用。

```toml
[dependencies]
lazy_static = {
    version = "1.4.0",
    features = ["spin_no_std]
}
```

全局初始化代码如下:

```rust
// os/src/batch.rs
lazy_static! {
    static ref APP_MANAGER: UPSafeCell<AppManager> = unsafe {
        UPSafeCell::new({
            extern "C": {
                fn _num_app();
            }
            let num_app_ptr = _num_app as usize as *const usize;
            let num_app = num_app_ptr.read_volatile();
            let mut app_start: [usize; MAX_APP_NUM + 1] = [0; MAX_APP_NUM + 1];
            let app_start_raw: &[usize] = core::slice::form_raw_parts(
                num_app_ptr.add(1), num_app + 1
            );
            app_start[..=num_app].copy_from_slice(app_start_raw);
            AppManager {
                num_app,
                currrent_app: 0,
                app_start,
            }
        })
    };
}
```

1. `read_volatile()`: called on this pointer to read the value at that memory location.
   - ensure that the data is always read from memory, even if the compiler might otherwise optimize it away.
2. `app_start_raw`: created by calling `core::slice::from_raw_parts()` with the pointer to the memory location where the application start addresses are stored. This pointer is obtained by adding 1 to the `num_app_ptr` pointer, which skips over the first value (which is the number of applications) to get to the start addresses.

`AppManager` 需要实现多种方法: `print_app_info get_current_app move_to_next_app load_app`

```rust
impl AppManager {
    pub fn print_app_info(&self) {
        println!("\x1b[38;5;45mNumber of apps:\x1b[0m \x1b[38;5;196m{}\x1b[0m", self.num_app);
        println!("\x1b[38;5;45mCurrent app:\x1b[0m \x1b[38;5;196m{}\x1b[0m", self.currrent_app);
        println!("\x1b[38;5;45mApp start addresses: ");
        for i in 0..self.num_app {
            println!("\x1b[38;5;45mApp {}:\x1b[0m \x1b[38;5;196m{:#x}\x1b[0m", i, self.app_start[i]);
        }
    }
    pub fn get_current_app(&self) -> usize {
        self.currrent_app
    }
    pub fn move_to_next_app(&self) -> !{
        self.currrent_app = (self.currrent_app + 1) % self.num_app;
    }
}
```

`load_app` 函数实现更麻烦一些: 将应用程序的数据从一块内存复制到一个可执行代码的内存区域

- `fence.i`: 取指屏障指令，**保证在它之后的取指过程必须能够看到在它之前的所有对于取指内存区域的修改，保证 CPU 访问的应用代码是最新的而不是 i-cache 中过时的内容**
  - 相当于: 手动清空上一个应用指令的缓存？

```rust
pub fn load_app(&self, idx: usize) {
	if idx >= self.num_app {
		panic!("Invalid app index");
	}

	println!("[kernel] Loading app_{}", idx);
	// clear
	unsafe{
		core::slice::from_raw_parts_mut(
			APP_BASE_ADDRESS as *mut u8,
			APP_SIZE_LIMIT
		).fill(0);
	}
	let start = self.app_start[idx];
	let end = self.app_start[idx + 1];

	// load the application code into memory
	let app_code = unsafe{
		core::slice::from_raw_parts(
			start as *const u8,
			end - start
		)
	};

	let app_dst = unsafe{
		core::slice::from_raw_parts_mut(
			APP_BASE_ADDRESS as *mut u8,
			app_code.len()
		)
	};
	app_dst.copy_from_slice(app_code);
	// memory fence about fetching the instruction memory
	unsafe {asm!("fence.i");}
}
```

`batch` 模块队外暴露出如下接口:

- `init`: 调用 `print_app_info`
- `run_next_app`: 加载并运行下一个应用程序

# 实现特权级的切换

## RISC-V 特权级切换

### 起因

特权级切换需要应用程序、操作系统和硬件一起协同

- 当启动应用程序的时候，需要初始化应用程序的用户态上下文，并能切换到用户态执行应用程序；
- 当应用程序发起系统调用（即发出 Trap）之后，需要到批处理操作系统中进行处理；
- 当应用程序执行出错的时候，需要到批处理操作系统中杀死该应用并加载运行下一个应用；
- 当应用程序执行结束的时候，需要到批处理操作系统中加载运行下一个应用（实际上也是通过系统调用`sys_exit` 来实现的）。

### 相关的控制状态寄存器

S 特权级中与 Trap 相关的 **控制状态寄存器** (CSR, Control and Status Register)

| CSR 名  | 该 CSR 与 Trap 相关的功能                                            |
| ------- | -------------------------------------------------------------------- |
| sstatus | `SPP` 等字段给出 Trap 发生之前 `CPU` 处在哪个特权级（S/U）等信息     |
| sepc    | 当 Trap 是一个异常的时候，记录 Trap 发生之前执行的最后一条指令的地址 |
| scause  | 描述 Trap 的原因                                                     |
| stval   | 给出 Trap 附加信息                                                   |
| stvec   | 控制 Trap 处理代码的入口地址                                         |

> 注意 `sstatus` 是 S 特权级最重要的 CSR，可以从多个方面控制 S 特权级的 CPU 行为和执行状态。

## 特权级切换的硬件控制机制

从用户特权级陷入到 S 特权级的时候，硬件会自动完成如下事情:

1. `sstatus` 的 `SPP` 字段会被修改为 CPU 当前的特权级
2. `sepc` 会被修改为 Trap 处理完成后默认会执行的下一条指令的地址
3. `scause/stval` 分别会被修改成这次 Trap 的原因以及相关的附加信息
4. CPU 会跳转到 `stvec` 所设置的 Trap 处理入口地址，并将当前特权级设置为 S，然后从 Trap 处理入口地址处开始执行

> `stvec` 64 位 CSR
>
> - MODE 位于 `[1:0]`
> - BASE 位于 `[63:2]`
>
> MODE\=\=0: `stcev`: Direct 模式。此时无论进入 S 模式的 Trap 原因，处理 Trap 的入口地址都是 `BASE<<2`

CPU 完成 Trap 处理后通过 `sret` 指令来完成

1. 将当前特权级按照 `sstatus` 的 `SPP` 字段修改
2. 跳转到 `sepc` 寄存器指向的那条指令，继续执行

## 用户栈与内核栈

在进入 S 特权级处理 Trap 之前，**必须保存原控制流的寄存器状态，一般通过内核栈保存，而不能是用户栈**

先对用户栈和内核栈进行定义

- `get_sp`: 获取栈顶指针

```rust
// os/src/batch.rs
const USER_STACK_SIZE: usize = 4096 * 2;
const KERNEL_STACK_SIZE: usize = 4096 * 2;
#[repr(align(4096))]
struct KernelStack {
    data: [u8; KERNEL_STACK_SIZE],
}
#[repr(align(4096))]
struct UserStack {
    data: [u8; USER_STACK_SIZE],
}
static KERNEL_STACK: KernelStack = KernelStack { data: [0; KERNEL_STACK_SIZE]};
static USER_STACK: UserStack = UserStack { data: [0; USER_STACK_SIZE]};
impl UserStack {
    fn get_sp(&self) -> usize {
        self.data.as_ptr() as usize + USER_STACK_SIZE
    }
}
impl KernelStack {
    fn get_sp(&self) -> usize {
        self.data.as_ptr() as usize + USER_STACK_SIZE
    }
}
```

## Trap

Trap 上下文，Trap 发生时需要保存物理资源内容，并将其放在一个名为 `TrapContext` 类型中

```rust
#[repr(C)]
pub struct TrapContext {
    pub x: [usize; 32],
    pub sstatus: Sstatus,
    pub sepc: usize,
}
```

- `x`: 32 长度的数组，用来保存 Trap 时的寄存器状态

### Trap 上下文的保存和恢复

具体实现 Trap 上下文保存和恢复的汇编代码如下:

```asm
.altmacro # enables the use of macro definitions in the code.

.macro SAVE_GP n
    sd x\n, \n*8(sp)
    # 如果n为1，则 x\n 将被展开为 x1
    # 如果n为4，则 \n*8(sp) 将被展开为 32(sp)
    # 寄存器 -> 内存
.endm
.macro LOAD_GP n # loads the value of a given general-purpose register from the kernel stack
    ld x\n, \n*8(sp)
.endm
.section .text
.globl __alltraps
.globl __restore

.align 2 # .align 指令的使用可以确保数据或代码在内存中按照正确的边界对齐，以提高访问速度和保证正确性
__alltraps:
    csrrw sp, sscratch, sp # 用于读取 CSR 中的值，并将值与一个给定的寄存器进行交换
# 将 sscratch 中的值读取到 sp 中，并将 sp 中的值写入到 sscratch 中

    addi sp, sp, -34*8 # 给 TrapContext 分配空间
    sd x1, 1*8(sp)
    # skip sp(x2), will save it later
    sd x3, 3*8(sp)
    # skip sp(x4), application does not use it
    # save x5~x31
    .set n, 5
    .rept 27
        SAVE_GP %n
        .set n, n+1
    .endr

    csrr t0, sstatus # csr  => rd
    csrr t1, sepc    # sepc => t1
    sd t0, 32*8(sp) # save csr  => 32*8(sp)
    sd t1, 33*8(sp) # save sepc => 33*8(sp)

    csrr t2, sscratch
    sd t2, 2*8(sp)  # save sscratch => 2*8(sp)

```

接着在 Trap 中使用这段 asm 代码

```rust
global_asm!(include_str!("trap.S"));

pub fn init() {
    extern "C" {
        fn __alltraps();
    }
    unsafe {
        stvec::write(__alltraps as usize, TrapMode::Direct);
    }
}
```

当 `trap_handler` 返回后需要从栈上 Trap 上下文进行恢复 `__restore`:

```asm
# after trap_handler
__restore:
    mv sp, a0  # sp -> kernel stack

    ld t0, 32*8(sp)
    ld t1, 32*8(sp)
    ld t2, 2*8(sp)
    csrw sstatus, t0  # csr-write
    csrw sepc, t1
    csrw sscratch, t2

    ld x1, 1*8(sp)
    ld x3, 3*8(sp)
    .set n, 5
    .rept 27
        LOAD_GP %n
        .set n, n+1
    .endr

    addi sp, sp, 34*8
    csrrw sp, sscratch, sp
    sret     # ret to user mode
```

恢复通用寄存器和 CSR

## Trap 分发与处理

Trap 在使用 Rust 实现的 `trap_handler` 中完成分发和处理:

```rust
#[no_mangle]
pub fn trap_handler(cx: &mut TrapContext) -> &mut TrapContext {
    let scause = scause::read();
    let stval = stval::read();

    match scause.cause() {
        Trap::Exception(Exception::UserEnvCall) => {
            cx.sepc += 4;
            cx.x[10] = syscall(cx.x[17], [cx.x[10], cx.x[11], cx.x[12]]) as usize;
        }
        Trap::Exception(Exception::StoreFault) | Trap::Exception(Exception::StorePageFault) => {
            println!("[kernel] PageFault in application, kernel killed it.");
            run_next_app();
        }
        Trap::Exception(Exception::IllegalInstruction) => {
            println!("[kernel] IlleagalInstruction in application, kernel killed it.");
            run_next_app();
        }
        _ => {
            panic!(
                "Unsupported trap {:?}, stval = {:#x}!",
                scause.cause(),
                stval
            );
        }
    }
    cx
}
```

- `Exception::UserEnvCall`: 用户环境调用中断，会执行用户态下的系统调用，将返回值存储在 `cx.x[10]` 寄存器中，并更新 `cx.sepc` 寄存器的值
  - `cx.spec += 4`: 用于跳过发生异常的指令
- `Exception::StoreFault` 和 `Exception::StorePageFault` 表示发生了存储异常或存储页故障

## 实现系统调用功能

**细化实现系统调用的处理函数**

```rust
// os/src/syscall/fs.rs
const FD_STDOUT: usize = 1;
pub fn sys_write(fd: usize, buf: *const u8, len: usize) -> isize {
    match fd {
        FD_STDOUT => {
            let slice = unsafe { core::slice::from_raw_parts(buf, len) };
            let str = core::str::from_utf8(slice).unwrap();
            print!("{}", str);
            len as isize
        },
        _ => {
            panic!("Unsupported fd in sys_write!");
        }
    }
}
// os/src/syscall/process.rs
pub fn sys_exit(xstate: i32) -> ! {
    println!("[kernel] Application exited with code {}", xstate);
    run_next_app()
}
```

# 执行应用程序

为 TrapContext 实现 `app_init_context` 方法

- 修改 `sepc` 寄存器为应用程序的入口点
- 清空寄存器状态
- 修改 `sp` 为栈指针
- 修改 `sstatus` 寄存器 `SPP` 为 `User`

```rust
impl TrapContext {
    pub fn set_sp(&mut self, sp: usize) {
        self.x[2] = sp;
    }
    pub fn app_init_context(entry: usize, sp: usize) -> Self {
        let mut sstatus = sstatus::read();
        sstatus.set_spp(SPP::User);
        let mut cx = Self {
            x: [0; 32],
            sstatus,
            sepc: entry,
        };
        cx.set_sp(sp);
        cx
    }
}
```

链接起 `__restore`，`*cx_ptr = cx` 将上下文放入到栈中，然后返回 `cx_ptr.as_mut().unwrap()` 强制转换成可变引用

```rust
impl KernelStack {
    fn get_sp(&self) -> usize {
        self.data.as_ptr() as usize + USER_STACK_SIZE
    }
    fn push_context(&self, cx: TrapContext) -> &'static mut TrapContext {
        let cx_ptr = (self.get_sp() - core::mem::size_of::<TrapContext>()) as *mut TrapContext;
        unsafe {
            *cx_ptr = cx;
        }

        unsafe{
            cx_ptr.as_mut().unwrap()
        }
    }
}
```

之后对 `__restore` 调用，恢复上下文

```rust
pub fn run_next_app() -> ! {
    let mut app_manager = APP_MANAGER.exclusive_access(); // 获取独占访问
    let current_app = app_manager.get_current_app();
    unsafe {
        app_manager.load_app(current_app);
    }
    app_manager.move_to_next_app();

    drop(app_manager);

    extern "C" {
        fn __restore(cx_addr: usize);
    }
    unsafe {
        __restore(KERNEL_STACK.push_context(
            TrapContext::app_init_context(APP_BASE_ADDRESS, USER_STACK.get_sp())
        ) as *const _ as usize);
    }
    panic!("Unreachable in batch::run_current_app!");
}
```

![](https://i.328888.xyz/2023/04/12/iXn4fQ.png)
