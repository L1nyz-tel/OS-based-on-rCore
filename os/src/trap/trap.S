.altmacro # enables the use of macro definitions in the code.

.macro SAVE_GP n
    sd x\n, \n*8(sp) 
    # 如果n为1，则 x\n 将被展开为 x1 
    # 如果n为4，则 \n*8(sp) 将被展开为 32(sp)
    # 寄存器 -> 内存
.endm
.macro LOAD_GP n # loads the value of a gp register from the kernel stack
    ld x\n, \n*8(sp)
.endm

.section .text
.globl __alltraps
.globl __restore

.align 2 # .align 指令的使用可以确保数据或代码在内存中按照正确的边界对齐，以提高访问速度和保证正确性
__alltraps:
    csrrw sp, sscratch, sp 
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

    mv a0, sp       # save sp => a0
    call trap_handler # trap_handler first param is from a0 <= sp

# after trap_handler
__restore:
    mv sp, a0  # sp -> kernel stack
    
    ld t0, 32*8(sp)
    ld t1, 33*8(sp)
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
    sret