.text
main:
    add.d $f8, $f4, $f6
    sub.d $f10, $f6, $f4
    mul.d $f12, $f4, $f6
    div.d $f14, $f6, $f4
    sdc1 $f6, 0($r9)
    ldc1 $f18, 8($r9)
    nop
.data
.align 3
DATA:
    .word 128
BUFFER:
    .space 32
