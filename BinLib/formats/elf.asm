.section .text
.globl main

.type main, @function
main:
    call srcc_entry
    ret

.type srcc_entry, @function
srcc_entry: