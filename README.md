# TELOS-based-on-rCore

TELOS-lab starts from March 18th

[notes](./notes/)

一起愉快地学习 Rust 吧（

- 使用 Rust 语言编写，具有内存安全和并发性能优势
- 基于 [rCore-Tutorial](https://rcore-os.github.io/rCore-Tutorial-Book-v3/index.html) 实现

## 目录结构

- `bootloader/`：Qemu 模拟器开机时用来初始化的引导加载程序
- `os/`：内核代码

## 构建和运行

构建和运行 rCore-OS 的步骤如下：

1. 在本地安装 Rust 和 QEMU
2. 进入 `os`，命令 `make run` 启动
    - GDB 调试请使用 `make debug-server` `make debug-client`

