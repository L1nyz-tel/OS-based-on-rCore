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
	@(OBJDUMP) -all $(KERNEL_FILE)

clean:
	@cargo clean

qemu: build
	@qemu-system-riscv64 \
		-machine virt \
		-nographic \
		-bios ../bootloader/rustsbi-qemu.bin \
		-device loader,file=$(BIN_FILE),addr=0x80200000 \
		-kernel $(BIN_FILE)

debug-server: build
	@qemu-system-riscv64 \
		-machine virt \
		-nographic \
		-bios ../bootloader/rustsbi-qemu.bin \
		-device loader,file=$(BIN_FILE),addr=0x80200000 \
		-kernel $(BIN_FILE) \
		-s -S

debug-client:
	@ riscv64-unknown-elf-gdb \
    	-ex 'file target/riscv64gc-unknown-none-elf/release/os' \
    	-ex 'set arch riscv:rv64' \
    	-ex 'target remote localhost:1234'

run: build qemu