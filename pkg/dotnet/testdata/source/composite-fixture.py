#!/usr/bin/env python3
"""Build an independent bounded PE export/component-layout regression fixture.

The ECMA metadata comes from the original compiled anycpu fixture. Runtime
corpus tests separately consume a real crossgen2 composite publication.
"""
from pathlib import Path
import struct
root=Path(__file__).resolve().parent.parent
original=(root/'anycpu.dll').read_bytes()
u16=lambda b,p:struct.unpack_from('<H',b,p)[0]
u32=lambda b,p:struct.unpack_from('<I',b,p)[0]
pe=u32(original,60);opt=pe+24;st=opt+u16(original,pe+20)
def offset(rva):
    for i in range(u16(original,pe+6)):
        p=st+i*40;va=u32(original,p+12);size=u32(original,p+16)
        if va<=rva<va+size:return u32(original,p+20)+rva-va
    raise ValueError('unmapped fixture RVA')
cli=offset(u32(original,opt+96+14*8))
md=offset(u32(original,cli+8));metadata=original[md:md+u32(original,cli+12)]
payload=bytearray(0x200+len(metadata))
def words(at,*values):struct.pack_into('<'+'I'*len(values),payload,at,*values)
base=0x1000
words(20,1,1,base+0x30,base+0x34,base+0x38)
words(0x30,base+0x80,base+0x40)
payload[0x40:0x4b]=b'RTR_HEADER\0'
words(0x80,0x00525452,16,0,3)
words(0x90,102,base+0xc0,16,109,base+0xd0,11,115,base+0xe0,16)
words(0xc0,base+0x180,base+0x1a0,base+0x190,base+0x1a4)
payload[0xd0:0xdb]=bytes([0,2,4,0xaa,2,4,1,2,8,0x3e,4])
words(0xe0,base+0x100,72,base+0x150,20)
words(0x100,72,0x50002,base+0x200,len(metadata),4)
words(0x150,0,1,103,base+0x170,4)
payload[0x170:0x174]=bytes([8,1,0,0])
payload[0x180:0x18c]=bytes(range(12));payload[0x190:0x198]=bytes(range(8))
words(0x1a0,3,2);payload[0x200:]=metadata
raw_size=(len(payload)+511)&~511
header=bytearray(512);header[:2]=b'MZ';struct.pack_into('<I',header,60,128)
header[128:132]=b'PE\0\0';struct.pack_into('<HHIIIHH',header,132,0xaa64,1,0,0,0,240,0x2022)
opt=152;struct.pack_into('<H',header,opt,0x20b);struct.pack_into('<Q',header,opt+24,0x180000000)
struct.pack_into('<II',header,opt+32,4096,512);struct.pack_into('<II',header,opt+56,(base+len(payload)+4095)&~4095,512)
struct.pack_into('<I',header,opt+108,16);struct.pack_into('<II',header,opt+112,base,0x80)
st=opt+240;header[st:st+8]=b'.rdata\0\0';struct.pack_into('<IIII',header,st+8,len(payload),base,raw_size,512);struct.pack_into('<I',header,st+36,0x40000040)
(root/'composite-pe.dll').write_bytes(header+payload+bytes(raw_size-len(payload)))
