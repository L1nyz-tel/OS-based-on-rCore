参照 [http://rcore-os.cn/rCore-Tutorial-deploy/docs/lab-0/guide/intro.html](http://rcore-os.cn/rCore-Tutorial-deploy/docs/lab-0/guide/intro.html)

- 使用 Rust 包管理器 cargo 创建一个 Rust 项目
- 移除 Rust 程序对操作系统的依赖，构建一个独立化可执行的程序
- 将程序的目标平台设置为 RISC-V
  - 代码将可以在 RISC-V 指令集的裸机（Bare Metal）上执行 Rust 代码
- 生成内核镜像、调整代码的内存布局并在 QEMU 模拟器中启动
- 封装如输出、关机等一些 SBI 的接口，方便后续开发

# 创建项目

编写操作系统时，需要使用到 Rust 一些不稳定的实验功能，所以此项目使用 nightly

但是官方无法保证 nightly 版本的稳定性，需要给 nightly 锁定一个日期

写入名为 `rust-toolchain` 文件

```Plain
nightly-2023-03-06
```

项目目录中执行 `cargo new os`，生成 os 项目目录

进入 os 文件夹，执行 `cargo run` 编译执行输出 hello world

# 移除标准库依赖

rust 默认链接标准库 std，依赖于操作系统，需要通过 `#![no_std]` 禁用 std 标准库

禁用标准库后，依赖标准库的一系列函数，如 `println` `panic_handler`... 都无法使用，需要手动写清楚这些必须函数

## panic 处理函数

`panic_handler` 在程序发生 panic 时调用，它默认使用标准库 std 中实现的函数并依赖于操作系统特殊的文件描述符，由于我们禁用了标准库，因此只能自己实现它

```rust
use core::panic::PanicInfo;

/// 当 panic 发生时会调用该函数
/// 我们暂时将它的实现为一个死循环
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
```

**`PanicInfo` 参数包含 panic 发生时候的文件名，代码行数，可选的错误信息。**

此函数从不返回，被标记成 **发散函数**，发散函数在 Rust 中的返回类型写作 `!`

## eh_personality 语义项

**语义项（Language Item）**：编译器内部所需的特殊函数或类型。

刚才的 `panic_handler` 也是一个语义项，需要告诉编译器当程序发生 panic 之后如何处理

而这个错误相关语义项 `eh_personality` ，其中 eh 是 Exception Handling 的缩写，它是一个标记某函数用来实现**堆栈展开**处理功能的语义项。这个语义项也与 panic 有关。

这个错误相关语义项 `eh_personality` ，其中 `eh` 是 `Exception Handling` 的缩写，它是一个标记某函数用来实现 **堆栈展开** 处理功能的语义项。这个语义项也与 panic 有关。

> 堆栈展开
>
> 通常当程序出现了异常时，从异常点开始会沿着 caller 调用栈一层一层回溯，直到找到某个函数能够捕获这个异常或终止程序。这个过程称为堆栈展开。
>
> 当程序出现异常时，我们需要沿着调用栈一层层回溯上去回收每个 caller 中定义的局部变量（这里的回收包括 C++ 的 RAII 的析构以及 Rust 的 drop 等）避免造成捕获异常并恢复后的内存溢出。
>
> 而在 Rust 中，panic 证明程序出现了错误，我们则会对于每个 caller 函数调用依次这个被标记为堆栈展开处理函数的函数进行清理。
>
> 这个处理函数是一个依赖于操作系统的复杂过程，在标准库中实现。但是我们禁用了标准库使得编译器找不到该过程的实现函数了。

在编写操作系统的最开始，设置为直接退出程序即可，如此而来，堆栈展开函数不会被调用

**因此在项目配置文件中直接将 dev release 配置的 panic 处理策略设为直接终止**

```toml
# panic 时直接终止，因为我们没有实现堆栈展开的功能
[profile.dev]
panic = "abort"

[profile.release]
panic = "abort"
```

执行 `cargo build` ，又一次发生错误

![](https://s1.ax1x.com/2023/03/17/ppG9bkD.png)

# 移除运行时环境依赖

## 运行时系统

> 对于大多数语言，他们都使用了**运行时系统**（Runtime System），这可能导致 `main` 函数并不是实际执行的第一个函数。
>
> 以 Rust 语言为例，一个典型的链接了标准库的 Rust 程序会首先跳转到 C 语言运行时环境中的 `crt0`（C Runtime Zero）进入 C 语言运行时环境设置 C 程序运行所需要的环境（如创建堆栈或设置寄存器参数等）。

去除了标准库的支持，我们就需要重写覆盖整个 `crt0` 入口点

```rust
//! - `#![no_main]`
//!   不使用 `main` 函数等全部 Rust-level 入口点来作为程序入口
#![no_main]

/// 覆盖 crt0 中的 _start 函数
/// 我们暂时将它的实现为一个死循环
#[no_mangle]
pub extern "C" fn _start() -> ! {
    loop {}
}
```

- `#![no_main]`: 告诉编译器不适用常规入口点
- `#![no_mangle]`: 告诉编译器禁用编译期间的名称重整，确保生成一个名为 `_start` 函数
- `extern "C"`: Rust FFI(Foreign Function Interface, 语言交互接口) 语法。表示此函数是一个 C 函数而非 Rust 函数

## 解决链接错误

需要告诉链接器，它不应该包含 C 语言运行时环境。我们可以选择提供特定的链接器参数（Linker Argument），也可以选择编译为裸机目标（Bare Metal Target），我们将沿着后者的思路在后面解决这个问题，即**直接编译为裸机目标不链接任何运行时环境**。

# 编译为裸机目标

选择一个底层没有操作系统的运行环境来进行编译，使用 rustup 来添加它，为目标下载一个标准库和 core 库

```shell
rustup target add riscv64imac-unknown-none-elf
```

构建独立式可执行程序

```shell
cargo build --target riscv64imac-unknown-none-elf
```

我们可以向 `os/.cargo/config` 中写入以下内容，从而简化以下 `--target` 这一条参数

```config
[build]
target = "riscv64imac-unknown-none-elf"
```

编译结果:

![](https://s1.ax1x.com/2023/03/17/ppGCz8J.png)

因为开发环境不是 riscv，所以暂时还无法运行此文件

# 生成内核镜像

## 安装 binutils 工具集

便于查看和分析生成的可执行文件，如 `objdump` `objcopy`

```shell
cargo install cargo-binutils
rustup component add llvm-tools-preview
```

![](https://s1.ax1x.com/2023/03/17/ppGPJPg.png)

## 生成镜像

我们之前生成的 elf 格式可执行文件有以下特点：

- 含有冗余的调试信息，使得程序体积较大
- 需要对 `Program Header` 部分进行手动解析才能知道各段的信息，而这需要我们了解 `Program Header` 的二进制格式，并以字节为单位进行解析

目前没有调试手段，也没有调试信息，同时也不会解析 elf 文件，所以可以使用工具 `rust-objcopy` **丢弃内核可执行文件中的元数据得到内核镜像**

```shell
rust-objcopy target/riscv64imac-unknown-none-elf/debug/os --strip-all -O binary target/riscv64imac-unknown-none-elf/debug/kernel.bin
```

- `--strip-all`: 丢弃所有符号表及其调试信息
- `-O binary`: 输出二进制文件

至此，编译并生成了内核镜像 `kernel.bin`

不过还需要完成两个工作：**调整内存布局** 和 **重写入口函数**

# 调整内存布局

编译出的用户程序默认被放到了 0x11000 开始的位置上

**而操作系统内核，一半需要将地址空间很在高地址上。并且在 QEMU 模拟的 RISC-V 中，DRAM 内存的物理地址是从 0x80000000 开始，有 128MB 大小。**

因此需要调整程序的内存布局，改变它的链接地址

> **程序的内存布局**
>
> 一般来说，一个程序按照功能不同会分为下面这些段：
>
> - `.text` 段：代码段，**存放汇编代码**
> - `.rodata` 段：只读数据段，顾名思义里面**存放只读数据，通常是程序中的常量**
> - `.data` 段：**存放被初始化的可读写数据，通常保存程序中的全局变量**
> - `.bss` 段：**存放被初始化为 0 的可读写数据（保存程序中那些未初始化的全局数据）**，与 .data 段的不同之处在于我们知道它要被初始化为 0，因此在可执行文件中只需记录这个段的大小以及所在位置即可，而不用记录里面的数据，也不会实际占用二进制文件的空间
> - `Stack`：栈，用来**存储程序运行过程中的局部变量，以及负责函数调用时的各种机制**。它从高地址向低地址增长
> - `Heap`：堆，用来**支持程序运行过程中内存的动态分配**，比如说你要读进来一个字符串，在你写程序的时候你也不知道它的长度究竟为多少，于是你只能在运行过程中，知道了字符串的长度之后，再在堆中给这个字符串分配内存
>
> 内存布局，也就是指这些段各自所放的位置。一种典型的内存布局如下：![](http://rcore-os.cn/rCore-Tutorial-deploy/docs/lab-0/pics/typical-layout.png)

## 编写链接脚本

**使用 链接脚本（Linker Script） 来调整链接器的行为，指定程序的内存布局**

Linker Script 相关参考资料

- [https://blog.louie.lu/2016/11/06/10 分鐘讀懂-linker-scripts/](https://blog.louie.lu/2016/11/06/10%E5%88%86%E9%90%98%E8%AE%80%E6%87%82-linker-scripts/)
- [https://sourceware.org/binutils/docs/ld/Scripts.html](https://sourceware.org/binutils/docs/ld/Scripts.html)

创建文件 `os/src/linker.ld`

```c
OUTPUT_ARCH(riscv)
ENTRY(_start)
BASE_ADDRESS = 0x80200000;

SECTIONS
{
    . = BASE_ADDRESS;
    skernel = .;

	stext = .;
    .text : {
        *(.text.entry)
        *(.text .text.*)
    }

	. = ALIGN(4K);
	etext = .;
	srodata = .;
    .rodata : {
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
    }

	. = ALIGN(4K);
	erodata = .;
	sdata = .;
    .data : {
        *(.data .data.*)
        *(.sdata .sdata.*)
    }

    . = ALIGN(4K);
    edata = .;
    .bss : {
	    *(.bss.stack)
	    sbss = .;
	    *(.bss .bss.*)
	    *(.sbss .sbss.*)
    }

    . = ALIGN(4K);
    ebss = .;
    ekernel = .;

	/DISCARD/ : {
		*(.eh_frame)
	}
}
```

> 时至今日我们已经不太可能将所有代码都写在一个文件里面。在编译过程中，我们的编译器和链接器已经给每个文件都自动生成了一个内存布局。这里，我们的链接工具所要做的是最终将各个文件的内存布局装配起来生成整个内核的内存布局。
>
> 到这里我们大概看懂了这个链接脚本在做些什么事情。首先是从 `BASE_ADDRESS` 即 `0x80200000` 开始向下放置各个段，依次是 `.text`，`.rodata`，`.data`，`.stack` 和 `.bss`。同时我们还记录下了每个段的开头和结尾地址，如 .text 段的开头、结尾地址分别就是符号 `stext` 和 `etext` 的值，我们接下来会用到。

- `*( )` 来表示将各个文件中所有符合括号内要求的输入段放在当前的位置。而括号内，你可以直接使用段的名字，也可以包含通配符 `*`

## 使用链接脚本

为了在编译时使用自定义的链接脚本 `linker.ld`，需要对 `os/.cargo/config` 加入以下配置

- 在链接时传入一个参数 `-T` 来指定使用哪个链接脚本

```config
# 使用我们的 linker script 来进行链接
[target.riscv64imac-unknown-none-elf]
rustflags = [
    "-C", "link-arg=-Tsrc/linker.ld", "-Cforce-frame-pointers=yes"
]
```

![](https://s1.ax1x.com/2023/03/17/ppGQzGR.png)

# 重写程序入口点 `_start`

在一开始，我们自己重写的入口点 `_start`，只让他进行死循环。现在，我们希望这个函数可以**为我们设置内核的运行环境，然后我们才真正开始执行内核的代码**

> 在 CPU 加电或 Reset 后，它首先会进行自检（POST, Power-On Self-Test），通过自检后会跳转到 **启动代码（Bootloader）** 的入口。在 `bootloader` 中，我们进行外设探测，并对内核的运行环境进行初步设置。随后，`bootloader` 会将内核代码从硬盘加载到内存中，并跳转到内核入口，正式进入内核。也就是说，**CPU 所执行的第一条指令其实是指 bootloader 的第一条指令。**

> [!Fileware 固件]

> 在计算中，固件是一种特定的计算机软件，它为设备的特定硬件提供低级控制进一步加载其他软件的功能。固件可以为设备更复杂的软件（如操作系统）提供标准化的操作环境，或者，对于不太复杂的设备，充当设备的完整操作系统，执行所有控制、监视和数据操作功能。
>
> **在基于 x86 的计算机系统中, BIOS 或 UEFI 是一种固件；在基于 RISC-V 的计算机系统中，OpenSBI 是一种固件。**

OpenSBI 固件运行在特权级别很高的计算机硬件环境中，即 **RISC-V 64 的 M Mode(CPU 加电后也就运行在 M Mode)**

我们将要实现的 OS 内核运行在 S Mode，而我们要支持的用户程序运行在 U Mode。

> [!RISC-V 特权级]
>
> RISC-V 共有 3 种特权级，分别是 **U Mode**（User / Application 模式）、**S Mode**（Supervisor 模式）和 **M Mode**（Machine 模式）。

OpenSBI 把 CPU 从 M Mode 切换到 S Mode，接着跳到一个固定地址 `0x80200000`，开始执行内核代码

> [!RISC-V 的 M Mode]
>
> Machine 模式是 RISC-V 中可以执行的最高权限模式。在机器态下运行的代码对内存、I/O 和一些对于启动和配置系统来说必要的底层功能有着完全的使用权。

> [!RISC-V 的 S Mode]
>
> Supervisor 模式是支持现代类 Unix 操作系统的权限模式，支持现代类 Unix 操作系统所需要的基于页面的虚拟内存机制是其核心。

介绍完这些，接下来是在 `_start` 函数中设置内核的运行环境

- [https://github.com/riscv-non-isa/riscv-asm-manual/blob/master/riscv-asm.md#pseudo-ops](https://github.com/riscv-non-isa/riscv-asm-manual/blob/master/riscv-asm.md#pseudo-ops)
- `.globl symbol_name`
  - emit symbol_name to symbol table (scope GLOBAL)
- `.section [{.text,.data,.rodata,.bss}]`
  - emit section (if not present, default .text) and make current

向 `os/src/entry.asm` 写入以下 asm 代码

```asm
 # os/src/entry.asm
     .section .text.entry
     .globl _start
 _start:
     li x1, 100
```

对以上汇编代码的解析:

- `.section .text.entry` 将这一行以后的内容全部放到一个名为 `.text.entry` 的段中
  - 一般来说，所有的代码都被放到一个名为 `.text` 的代码段中
  - 在此处将其命名为 `.text.entry` 从而区别于其他 `.text`: 为了**确保该段被放置在相比任何其他代码段更低的地址上，这样作为内核的入口点，这段指令才能最先被执行**
- `.globl _start` 告知编译器 `_start` 是一个全局符号，因此可以被其他目标文件使用

## 分配并使用启动栈

我们在 `entry.asm` 中分配启动栈空间，并在控制权被转交给 Rust 入口之前将栈指针 `sp` 设置为栈顶的位置

```asm
# os/src/entry.asm
    .section .text.entry
    .globl _start
_start:
    la sp, boot_stack_top
    call rust_main
    .section .bss.stack
    .globl boot_stack_lower_bound
boot_stack_lower_bound:
    .space 4096 * 16
    .globl boot_stack_top
boot_stack_top:
```

- `boot_stack_lower_bound` **栈能够增长到的下限位置**
- `.space 4096 * 16` 在内核的内存布局中预留了一块大小为 4096\*16 字节(64KB) 空间用作程序的栈空间
- `boot_stack_top` **栈顶的位置**

接下来修改 main.rs，加载 asm 并且能正常工作

文档里说使用 `#![feature(global_asm)]`，但是这一条在 2023 版本的 rust 中会导致编译报错:

![](https://s1.ax1x.com/2023/03/17/ppGHQje.png)

原来的特性现在已经不适用，需要更改成以下代码:

```rust
//!   内嵌整个汇编文件
use core::arch::global_asm;
global_asm!(include_str!("entry.asm"));
```

同时，将 `_start` 更改成 `rust_main`，与 asm 中代码对应上

内核初始化中，需要先完成对 `.bss` 段的清零。在 `rust_main` 的开头完成这一工作

```rust
fn clear_bss() {
    extern "C" {
        fn sbss();
        fn ebss();
    }
    (sbss as usize..ebss as usize).for_each(|a| {
        unsafe { (a as *mut u8).write_volatile(0) }
    });
}
#[no_mangle]
pub fn rust_main() -> ! {
    clear_bss();
    loop {}
}
```

在函数 `clear_bss` 中，找到全局符号 `sbss` `ebss`(它们由链接脚本 `linker.ld` 给出)，分别指向需要被清零的 `.bss` 段的起始和终止地址，然后遍历改地址区间并逐字节进行清零即可

到现在为止我们终于将一切都准备好了，接下来就要配合 OpenSBI 运行我们的内核.jpg

# 使用 QEMU 运行内核

## 使用 OpenSBI

新版 QEMU 中内置 OpenSBI 固件，**它主要负责在操作系统运行前的硬件初始化和加载操作系统的功能**

使用命令简单尝试一下:

![](https://s1.ax1x.com/2023/03/17/ppGHH4x.png)

在 qemu-system-riscv64 模拟的 qemu virt machine 硬件上将 OpenSBI 固件跑起来

## 加载内核镜像

为了确保我们能够成功跑起来内核里面的代码，需在 `rust_main` 中加上一些简单的输出

**清华文档里使用的是 `llvm_asm`，而现如今 `llvm_asm!` 宏因为 Rust 版本更新迭代，已经不存在了，只有 `asm!` 宏**

asm! 和 llvm_asm! 宏所达到的效果差不多，但是参数有一些变化，到这里需要查看文档:

- [https://doc.rust-lang.org/core/arch/macro.asm.html](https://doc.rust-lang.org/core/arch/macro.asm.html)
- [https://doc.rust-lang.org/nightly/rust-by-example/unsafe/asm.html](https://doc.rust-lang.org/nightly/rust-by-example/unsafe/asm.html)
- [https://doc.rust-lang.org/nightly/reference/inline-assembly.html](https://doc.rust-lang.org/nightly/reference/inline-assembly.html)
- [https://juejin.cn/post/7064837070375616519](https://juejin.cn/post/7064837070375616519)
  %%- [https://blog.csdn.net/m0_50450598/article/details/123153739](https://blog.csdn.net/m0_50450598/article/details/123153739)%%

`ecall`:

- 有些寄存器只能在 m 模式下设置和访问，如果 s 模式想要使用某个功能，只能先回到 m 模式然后再进行相应的设置。
- OpenSBI 定义了 s 模式和 m 模式之间功能调用的接口，s 模式通过执行"ecall"指令回到 m 模式使用相关功能

把 llvm_asm! 替换成 asm! 参照如下写法

```rust
pub fn console_putchar(ch: u8){
    let _ret: usize;
    let arg0: usize = ch as usize;
    let arg1: usize = 0;
    let arg2: usize = 0;
    let id: usize = 1;
    unsafe {
        asm!(
            "ecall",
            inout("x10") arg0 => _ret,
            in("x11") arg1,
            in("x12") arg2,
            in("x17") id,
        );
    }
}
```

现在生成内核镜像需要通过多条命令来完成，所以可以通过编写 Makefile 来简化这一过程

```Makefile
TARGET := riscv64imac-unknown-none-elf
MODE   := debug
KERNEL_FILE := target/$(TARGET)/$(MODE)/os
BIN_FILE := target/$(TARGET)/$(MODE)/kernel.bin

OBJDUMP := rust-objdump --arch-name=riscv64
OBJCOPY := rust-objcopy --binary-architecture=riscv64

.PHONY: doc kernel build clean qemu run

build: $(BIN_FILE)

doc:
	@cargo doc --document-private-items

kernel:
	@cargo build

# $@ <=> $(BIN_FILE)
$(BIN_FILE): kernel
	@$(OBJCOPY) $(KERNEL_FILE) --strip-all -O binary $@

asm:
	@(OBJDUMP) -d $(KERNEL_FILE) | less

clean:
	@cargo clean

qemu: build
	@qemu-system-riscv64 \
		-machine virt \
		-nographic \
		-bios ../bootloader/rustsbi-qemu.bin \
		-device loader,file=$(BIN_FILE),addr=0x80200000 \
		-kernel $(BIN_FILE)

run: build qemu
```

- `-machine virt` 表示将模拟的 64 位 RISC-V 计算机设置为名为 `virt` 的虚拟计算机
- `-nographic` 表示模拟器不需要提供图形界面，而只需要对外输出字符流
- `-bios` 可以设置 Qemu 模拟器开机时用来初始化的引导加载程序（bootloader），这里我们使用预编译好的 `rustsbi-qemu.bin` ，它需要被放在与 `os` 同级的 `bootloader` 目录下，该目录可以从每一章的代码分支中获得
- `-device`
  - `loader` 属性可以在 Qemu 模拟器开机之前将一个宿主机上的文件载入到 Qemu 的物理内存的指定位置中
  - `file` 和 `addr` 属性分别可以设置待载入文件的路径以及将文件载入到的 Qemu 物理内存上的物理地址

`make run` 运行，成功输出 `OK`:

![](https://s1.ax1x.com/2023/03/19/ppYGXgH.png)

原本输出不了 `OK`，查询 github issue 发现 `QEMU` 串口重定向的问题，在 `qemu-system-riscv64` 选项后增加 `-kernel $(BIN_FILE)` 即可

## 进行 GDB 调试

- `-s` 使 Qemu 监听本地 TCP 端口 1234 等待 GDB 客户端连接
- `-S` 使 Qemu 收到 GDB 请求后再开始运行

```shell
 riscv64-unknown-elf-gdb \
    -ex 'file target/riscv64gc-unknown-none-elf/release/os' \
    -ex 'set arch riscv:rv64' \
    -ex 'target remote localhost:1234'
```

1. `x/10i $pc` 的含义是从当前 PC 值的位置开始，在内存中反汇编 10 条指令
2. `p/x $t0` 以 16 进制打印寄存器 `t0` 的值
3. `b *0x80200000` 在特定的地址打上断点
4. `c` continue 让 Qemu 向下运行直到遇到一个断点

# 接口封装和代码整理

## 使用 OpenSBI 提供的服务

OpenSBI 不仅起到了 bootloader 的作用，**还为我们提供了一些底层系统服务供我们在编写内核时使用，以简化内核实现并提高内核跨硬件细节的能力**

这层底层系统服务接口称为 SBI(Supervisor Binary Interface)，是 S Mode 的 OS 和 M Mode 执行环境之间的标志接口约定

[OpenSBI 文档](https://github.com/riscv-non-isa/riscv-sbi-doc/blob/master/riscv-sbi.adoc) 中包含了一些以 C 函数格式给出的我们可以调用的接口，如:

```c
void sbi_console_putchar(int ch)
```

实际过程是: 运行在 S 态的 OS 通过 ecall 发起 SBI 调用请求，RISC-V CPU 会从 S 态跳转到 M 态的 OpenSBI 固件，OpenSBI 会检查 OS 发起的 SBI 调用编号

如果编号在 0-8，则进行处理，否则交由我们自己的中断处理程序

执行 `ecall` 前需要指定 SBI 调用的编号，传递参数。

- `a7(x17)`: SBI 调用编号
- `a0(x10) a1(x11) a2(x12)`: SBI 调用参数
- 输入部分，我们分别通过寄存器 `x10`、`x11`、`x12` 和 `x17`（这四个寄存器又名 `a0`、`a1`、`a2` 和 `a7`） 传入参数 `arg0`、`arg1`、`arg2` 和 `which` ，其中前三个参数分别代表接口可能所需的三个输入参数，最后一个 `which` 用来区分我们调用的是哪个接口（SBI Extension ID）。
- 这里之所以提供三个输入参数是为了将所有接口囊括进去，对于某些接口有的输入参数是冗余的，比如 `sbi_console_putchar` 由于只需一个输入参数，它就只关心寄存器 `a0` 的值。

`os/src/sbi.rs`

```rust
// 暂时允许未使用的变量或函数
#![allow(unused)]

// SBI 调用
#[inline(always)]

fn sbi_call(which:usize, arg0: usize, arg1: usize, arg2: usize) -> usize {
    let ret;
    unsafe {
        asm! {
            "ecall",
            inout("x10") arg0 => ret,
            in("x11") arg1,
            in("x12") arg2,
            in("x17") which,
        }
    }
    ret
}
```

> 通常编译器按照某种规范去翻译所有的函数调用，这种规范被称为 [Calling Convention](https://en.wikipedia.org/wiki/Calling_convention) 。值得一提的是，为了确保被调用函数能正确执行，我们需要预先分配一块内存作为**调用栈** ，后面会看到调用栈在函数调用过程中极其重要。
>
> 对于参数比较少且是基本数据类型的时候，我们从左到右使用寄存器 `a0` 到 `a7` 就可以完成参数的传递。具体规范可参考 [RISC-V Calling Convention](https://riscv.org/wp-content/uploads/2015/01/riscv-calling.pdf)。

接下来利用 sbi_call 函数结合 OpenSBI 文档实现对应的接口，对 `console_putchar` `console_getchar` `shutdown` 进行实现

| Function Name              | SBI Version | FID | EID       | Replacement EID |
| -------------------------- | ----------- | --- | --------- | --------------- |
| sbi_set_timer              | 0.1         | 0   | 0x00      | 0x54494D45      |
| sbi_console_putchar        | 0.1         | 0   | 0x01      | N/A             |
| sbi_console_getchar        | 0.1         | 0   | 0x02      | N/A             |
| sbi_clear_ipi              | 0.1         | 0   | 0x03      | N/A             |
| sbi_send_ipi               | 0.1         | 0   | 0x04      | 0x735049        |
| sbi_remote_fence_i         | 0.1         | 0   | 0x05      | 0x52464E43      |
| sbi_remote_sfence_vma      | 0.1         | 0   | 0x06      | 0x52464E43      |
| sbi_remote_sfence_vma_asid | 0.1         | 0   | 0x07      | 0x52464E43      |
| sbi_shutdown               | 0.1         | 0   | 0x08      | 0x53525354      |
| _RESERVED_                 |             |     | 0x09-0x0F |

```rust
const SBI_SET_TIMER : usize = 0;
const SBI_CONSOLE_PUTCHAR : usize = 1;
const SBI_CONSOLE_GETCHAR : usize = 2;
const SBI_CLEAR_IPI : usize = 3;
const SBI_SEND_IPI : usize = 4;
const SBI_REMOTE_FENCE_I : usize = 5;
const SBI_REMOTE_SFENCE_VMA : usize = 6;
const SBI_REMOTE_SFENCE_VMA_ASID : usize = 7;
const SBI_SHUTDOWN : usize = 8;

fn sbi_call(which:usize, arg0: usize, arg1: usize, arg2: usize) -> usize {
    ......
}

// 向控制台输出一个字符
// 注意: 不能直接使用 Rust 中的 char 类型
pub fn console_putchar(c : usize) {
    sbi_call(SBI_CONSOLE_PUTCHAR, c, 0, 0);
}

// 从控制台读取一个字符
// 没有读取到字符则返回 -1
pub fn console_getchar() -> usize {
    sbi_call(SBI_CONSOLE_GETCHAR, 0, 0, 0);
}

// 关闭操作系统
pub fn shutdown() {
    sbi_call(SBI_SHUTDOWN, 0, 0, 0);
    unreachable!()
}
```

接下来，使用 `console_putchar` 实现格式化输出，为后面的调试提供方便！

## 实现格式化输出

来实现自己的 `println!` `print!` 宏！

关于格式化输出，Rust 中提供了一个接口 `core::fmt::Write`，需要实现函数：

为 Write 实现 write_str 方法

`os/src/conosle.rs`

```rust
// use core::fmt::Write;

use crate::sbi::*;
use core::fmt::{self, Write};

struct Stdout;

impl Write for Stdout {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for c in s.chars() {
            console_putchar(c as usize);
        }
        Ok(())
    }
}


/// 打印由 [`core::format_args!`] 格式化后的数据
///
/// [`print!`] 和 [`println!`] 宏都将展开成此函数
///
/// [`core::format_args!`]: https://doc.rust-lang.org/nightly/core/macro.format_args.html

pub fn print(args: fmt::Arguments) {
    Stdout.write_fmt(args).unwrap();
}

/// 实现类似于标准库中的 `print!` 宏
///
/// 使用实现了 [`core::fmt::Write`] trait 的 [`console::Stdout`]
#[macro_export]
macro_rules! print {
    ($fmt: literal $(, $($arg: tt)+)?) => {
        $crate::console::print(format_args!($fmt $(, $($arg)+)?));
    }
}

/// 实现类似于标准库中的 `println!` 宏
///
/// 使用实现了 [`core::fmt::Write`] trait 的 [`console::Stdout`]
#[macro_export]
macro_rules! println {
    ($fmt: literal $(, $($arg: tt)+)?) => {
        $crate::console::print(format_args!(concat!($fmt, "\n") $(, $($arg)+)?));
    }
}
```

在 `console` 子模块中编写 `println!` 宏。

结构体 `Stdout` 不包含任何字段，被称为 **类单元结构体**

`core::fmt::Write` 中包含一个用来实现 `println!` 宏很好用的 `write_fmt` 方法，为此需要为 `Stdout` 实现 `Write` trait，`write_str` 方法必须实现，只需遍历传入 `&str` 中的每一个字符进行调用 `console_putchar` 即可

之后 `Stdout` 便可调用 `Write` trait 提供的 `write_fmt` 方法，进而实现 `print` 函数

之后，由 `#[macro_export]` 标记的函数 `print!` `println!` 中会调用 `print` 函数完成其正常功能

- 关于**声明式宏**的参考: [https://course.rs/advance/macro.html?highlight=macro\_#声明式宏-macro_rules](https://course.rs/advance/macro.html?highlight=macro_#%E5%A3%B0%E6%98%8E%E5%BC%8F%E5%AE%8F-macro_rules)
  - `#[macro_export]` 注释将宏进行了导出，这样其它的包就可以将该宏引入到当前作用域中，然后才能使用
  - `($fmt: literal $(, $($arg: tt)+)?) => { ... }` 涉及到 Rust 的**模式解析**

## 整理 panic 处理模块

最后，用刚刚实现的格式化输出和关机的函数，将 `main.rs` 中处理 panic 的语义项抽取并完善到 `panic.rs` 中

Rust 将错误分为可恢复和不可恢复错误两大类。这里我们主要关心不可恢复错误。

借助前面实现的 `println!` 宏和 `shutdown` 函数，我们可以在 `panic` 函数中打印错误信息并关机：

`os/src/panic.rs`

```rust
//! 代替 std 库，实现 panic 和 abort 的功能

use core::panic::PanicInfo;
use crate::sbi::shutdown;

/// 打印 panic 的信息并 [`shutdown`]
///
/// ### `#[panic_handler]` 属性
/// 声明此函数是 panic 的回调
#[panic_handler]
fn panic_handler(info: &PanicInfo) -> ! {
    // `\x1b[??m` 是控制终端字符输出格式的指令，在支持的平台上可以改变文字颜色等等，这里使用红色
    // 参考：https://misc.flogisoft.com/bash/tip_colors_and_formatting
    //
    // 需要全局开启 feature(panic_info_message) 才可以调用 .message() 函数
    println!("\x1b[1;31mpanic: '{}'\x1b[0m", info.message().unwrap());
    shutdown()
}

/// 终止程序
///
/// 调用 [`panic_handler`]
#[no_mangle]
extern "C" fn abort() -> ! {
    panic!("abort()")
}
```

## 检验成果

在 main.rs 中调用我们实现的 `println!` 和 `panic!`

```rust
/// Rust 的入口函数
#[no_mangle]
pub extern "C" fn rust_main() -> ! {
    println!("Hello rCore-Tutorial!");
    panic!("end of rust_main")
}
```

在命令行中输入 `make run`，我们成功看到了 `println` 宏输出的 `Hello rCore-Tutorial!` 和一行红色的 `panic: 'end of rust_main'`！

![](https://s1.ax1x.com/2023/03/20/pptjokD.png)
