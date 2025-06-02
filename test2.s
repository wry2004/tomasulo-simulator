.text
main:
    ldc1   $f2, 0($r1)
    add.d  $f4, $f2, $f6
    sub.d  $f8, $f4, $f6
    mul.d  $f10, $f8, $f2
    div.d  $f12, $f10, $f4
    sw   $f12, 8($r1)
    nop
.data
.align 3
DATA:
    .word 128
BUFFER:
    .space 32
