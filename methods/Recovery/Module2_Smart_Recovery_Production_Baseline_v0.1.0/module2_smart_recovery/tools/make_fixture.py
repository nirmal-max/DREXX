from pathlib import Path
p=Path('fixture.bin')
b=bytearray(4096)
b[510:512]=b'\x55\xaa'
b[446+4]=0x07
b[446+8:446+12]=(1).to_bytes(4,'little')
b[446+12:446+16]=(7).to_bytes(4,'little')
p.write_bytes(b)
print(p.resolve())
