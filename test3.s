.text
main:
    ldc1   $f2, 0($r1)
    add.d  $f4, $f8, $f6
    sub.d  $f6, $f12, $f10
    mul.d  $f12, $f14, $f8
    div.d  $f14, $f10, $f8
    sw   $f16, 8($r1)
    nop
.data
.align 3
DATA:
    .word 128
BUFFER:
    .space 32
