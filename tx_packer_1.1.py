from Crypto.Cipher import AES
from Crypto.Util import Counter
import struct

import hashlib
from binascii import hexlify, unhexlify
"""
typedef struct boot_dat_hdr
{
	unsigned char ident[0x10];
	unsigned char sha2_s2[0x20];
	unsigned int s2_dst;
	unsigned int s2_size;
	unsigned int s2_enc;
	unsigned char pad[0x10];
	unsigned int s3_size;
	unsigned char pad2[0x90];
	unsigned char sha2_hdr[0x20];
} boot_dat_hdr_t;
"""

def aes_ctr_dec(buf, key, iv):
    ctr = Counter.new(128, initial_value=long(iv.encode('hex'), 16))
    return AES.new(key, AES.MODE_CTR, counter=ctr).encrypt(buf)

def aes_ctr_enc(buf, key, iv):
    ctr = Counter.new(128, initial_value=long(iv.encode('hex'), 16))
    return AES.new(key, AES.MODE_CTR, counter=ctr).decrypt(buf)

boot = open('boot_recompiled.dat', 'wb')
stage2 = open('stage2_40020000.bin', 'rb').read()
e0sHashBytes = b""

#ident
e0sHashBytes += b'\x54\x58\x20\x42\x4F\x4F\x54\x00\x00\x00\x00\x00\x56\x31\x2E\x31'
#sha-256 of stage2_40020000.bin
sha256 = hashlib.new('sha256')
sha256.update(stage2)
e0sHashBytes += sha256.digest()
# todo: write s2_dst, hardcoded :\
e0sHashBytes += b'\x00\x00\x02\x40'
# write s2_size
e0sHashBytes += struct.pack('I', len(stage2))
# write s2_enc
e0sHashBytes += struct.pack('I', 1)
# 0x10 size padding
e0sHashBytes += b'\x00' * 0x10
# s3_size?
e0sHashBytes += b'\x20\x2F\xED\x00'
# 0x90 size padding
e0sHashBytes += b'\x00' * 0x90
# write all that data
boot.write(e0sHashBytes)
# calculate e0ssha256
sha256 = hashlib.new('sha256')
sha256.update(e0sHashBytes)
boot.write(sha256.digest())
# stage2
boot.write(aes_ctr_enc(stage2, unhexlify("47E6BFB05965ABCD00E2EE4DDF540261"), unhexlify("8E4C7889CBAE4A3D64797DDA84BDB086")))
# data
boot.write(aes_ctr_enc(open("data_repacked_80000000.bin", "rb").read(), unhexlify("8D6FEABE0F3936145A474D3F05D33679"), unhexlify("2846EFA9DACB065C51C71C154F0E9EA2")))
# fb
boot.write(aes_ctr_enc(open("fb_F0000000.bin", "rb").read(), unhexlify("27BABEE3DCFEF100C744A2388B57E957"), unhexlify("0B88AC25AFAF9B92D81372331AD66E24")))
# arm64
boot.write(aes_ctr_enc(open("arm64_80FFFE00.bin", "rb").read(), unhexlify("51A39F0B46BAE4691AD39A698146E865"), unhexlify("7A307ED7F1ECC792F0E821ECD6999853")))
# write rest of boot.dat og from 0x571e50 onwards
with open("boot.dat", "rb") as fh:
	fh.seek(0x571E50, 0)
	boot.write(fh.read())

boot.close()
