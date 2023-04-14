.text
.globl _start

_start:
    li a0, 10
    li t0, 0
.L1:
    addi t0, t0, 1
    addi a0, a0, -1

    bnez a0, loop

    li a1, 1
    mv a0, t0
    ecall

    li a0, 10
    ecall
