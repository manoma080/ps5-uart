import pyftdi.serialext
import struct
from pathlib import Path
from tqdm import trange

class Stuff:
    def __init__(self):
        # XXX this needs to be connected to titania uart1
        self.port = pyftdi.serialext.serial_for_url('ftdi://ftdi:232:AD5V3R0X/1', baudrate=460800)
        self.port.timeout = .05

    def _read(self, size: int) -> bytes:
        return self.port.read(size)

    def _read_all(self, size: int) -> bytes:
        buf = b''
        while len(buf) != size:
            buf += self._read(size - len(buf))
        return buf

    def _write(self, buf: bytes):
        return self.port.write(buf)

    def rom_cmd(self, cmd: str):
        cmd += '\n'
        self._write(bytes(cmd, 'ascii'))
        echo_len = len(cmd)
        echo = self._read_all(echo_len)
        #return self.read_until(b'\n>')

    def info(self):
        self.rom_cmd('run')
        rv = self.read_until(b'\n>')
        return rv

    def run(self):
        self.rom_cmd('run')
        rv = self.read_until(b'\n>')
        return int(rv.split(b'\n')[0], 16)

    def xm_wait_c(self):
        while self._read(1) != self.CRC:
            pass

    def read_until(self, stop):
        buf = b''
        while True:
            b = self._read_all(1)
            if len(b) == 0: break
            buf += b
            if buf.endswith(stop): break
        return buf

    def xm_eot(self):
        self._write(self.EOT)
        rv = self.xm_read()
        # XXX this read_until prompt should be within rom_cmd
        if rv == self.EOT:
            return rv, None
        return rv, self.read_until(b'\n>')

    def xm_crc(self, buf):
        crc = 0
        for b in buf:
            crc ^= b << 8
            for i in range(8):
                if crc & 0x8000:
                    crc = (crc << 1) ^ 0x1021
                else:
                    crc <<= 1
                crc &= 0xffff
        return crc

    #'''

    SOH = b'\1'
    STX = b'\2'
    EOT = b'\4'
    ACK = b'\6'
    NAK = b'\x15'
    CRC = b'C'

    BLOCK_SIZE = 1024

    def xm_read(self):
        end_chars = (self.NAK, self.ACK, self.EOT, self.CRC)
        buf = b''
        while True:
            b = self._read_all(1)
            if len(b) == 0: break
            buf += b
            if b in end_chars: break
        return buf

    def xm_read_lines(self):
        return self.xm_read().split(b'\n')

    def xm_send(self, buf: bytes):
        block_len = self.BLOCK_SIZE
        self.xm_wait_c()
        pos = 0
        block_idx = 1
        while pos < len(buf):
            xfer_len = min(block_len, len(buf) - pos)
            hdr = self.STX + block_idx.to_bytes(1) + (~block_idx & 0xff).to_bytes(1)
            data = buf[pos:pos+xfer_len]
            if xfer_len < block_len:
                data += b'\0' * (block_len - xfer_len)
            crc = self.xm_crc(data)
            block = hdr + data + crc.to_bytes(2, 'big')
            #print(f'block {block_idx} {pos:x}')
            #print(block.hex())
            self._write(block)
            r = self.xm_read_lines()
            '''
            for l in r[:-1]: print('line', l)
            print('response', r[-1])
            #'''
            if r[-1] != self.ACK:
                if r[-1] in (self.NAK, self.CRC):
                    self.xm_eot()
                if len(r) > 1:
                    return int(r[0], 16)
                return -1
            pos += xfer_len
            block_idx += 1
            block_idx &= 0xff
        rv = self.xm_eot()
        #print('eot rv', rv)
        if rv[0] != self.ACK: return -1
        return 0
    #'''

shit=bytes.fromhex('''
1D 33 47 77 00 01 FF 00 00 70 17 00 00 28 00 00
58 2E 24 20 EC D9 19 90 8E CD 73 D7 A5 E8 CB A3
C1 4F 7C 37 D6 26 49 A5 9F 2D 40 25 1F 76 2F 19
C4 47 5E 18 00 48 D3 EA 4E 81 A0 A4 6E 2E 73 3B
7A 70 4C 7C 7F 87 96 D8 AC A5 93 CF 3A 8E 29 93
C6 3A C2 AA 6F 96 49 77 FD 62 EF 70 B9 EF D1 97
B1 CC 91 41 EE 97 59 E0 2A 55 60 C9 E3 43 EB 08
00 01 47 11 ED E9 6A D9 89 9B F2 2D 9B 2A DB D2
60 5A F6 02 DB 2E E0 A2 48 A1 69 AF 1E C1 FF 78
6C 77 2F 12 D7 54 89 33 74 00 59 56 59 B4 DD 0C
5D 09 52 BA 84 FE BE 8B 8E 2A 7E D6 A0 94 C2 82
06 D1 7D BF D4 32 1D 74 FF B3 73 CB CB 13 A2 A9
9D DE 55 2B 50 14 99 09 C2 1B 54 60 7F 08 B9 27
CC 0B 8A 8F 98 3F 8D 83 10 C8 46 28 B5 F5 12 79
05 0F 94 6C 4D 51 4B CA 63 A8 88 C0 77 AE 5E 6A
07 FE 6B 32 39 01 9F 78 17 05 FC B2 A3 92 9A B8
70 26 9B 36 23 E4 7D 55 F3 2D A4 87 1A 32 6E EB
CA 8C 03 E7 E3 80 3E 47 A5 73 2E EB 6D 09 46 5B
E3 5C BA F2 A9 F9 38 2A 01 C2 68 1C 9E D3 EA 2E
47 7C 39 37 E3 60 D0 91 F1 C4 BA CE 7C E6 30 33
52 97 79 9B DE BF 93 B6 B3 14 BB 99 F0 FC 57 5A
DC DB 3C 5B BF 1C 00 3E 77 E8 52 1B 9A F8 D7 D0
4B E1 0A 94 94 EE 1B 92 A6 FD F4 D4 0E EF 4D ED
51 60 A0 36 80 C3 FE 2A 55 7C 5D 4A 08 0B 36 9D
91 66 ED 20 14 49 7C A8 5A B1 13 C4 19 44 2F 1E
8E 89 38 F6 B0 4B 7D 6D 77 BA 0D 69 11 52 94 8D
48 4B E8 AD 5B 9E 2B B8 47 A2 DB 46 25 95 F0 7E
1C 12 A9 F0 81 FE 52 D7 D3 4B 56 0B 1E 07 FD CF
76 D4 F6 C6 47 B7 97 2B 89 DA 07 3A C8 94 89 76
19 38 1D 9E 97 B6 C5 CD E3 78 A4 05 0B 44 7E F4
9C 8E 23 32 01 E0 A9 B1 D1 C1 64 0D BF 98 6C 02
C0 81 5B F2 3F F1 8D CF EC 0C 9B DD FD 3C 1D 70
34 22 34 3D 79 A9 0F E9 86 EC 26 5D 24 51 A4 E5
EE A3 61 AC 36 59 BB FD 7F 2C AC E4 42 C0 F2 A4
8B F3 EB C3 25 43 E5 56 19 CB E6 5F CB 25 83 34
F1 F9 BD 7E 84 F0 4B 55 1A 4E 70 84 C3 1C 00 4C
81 3D 74 81 D3 1A F0 BC B8 A2 97 EF F2 B7 E9 DD
63 F1 02 B2 37 76 A7 3A 63 08 64 BA BA 15 0C AC
5A 3D DE FF DC AD 1C 87 58 F2 CB 45 30 E7 93 C6
9D 09 AA 53 21 2D 4D 96 EE 37 D3 56 F9 3C 95 70
26 70 E8 0F 7C 18 11 DB B3 94 21 A3 FB B5 E4 0E
17 04 34 14 D6 27 E5 58 B0 9F A1 5B 19 7D C3 44
4A 51 A6 ED FD AE D2 62 29 69 2D 6C E4 7F A0 BC
65 E0 7F 04 6F BA AB 03 4A 60 81 05 F8 AF AC 59
CF 4E 47 66 20 8B 60 3C 6F F9 1B B3 98 39 C0 BF
52 E8 4B 5C 39 31 A3 93 59 CC 5C 5C 7A 4D 20 99
9F 9B 62 DD AE 00 71 3D 6D 0A 4F 9A 0F 94 9C 66
F8 97 45 91 3E 78 BE 4A 46 CE C9 4B 4C FF 98 64
84 94 97 17 7C 92 A9 23 3F B4 37 B2 1D 0A 79 68
E6 7A FE 7B FC A6 B4 10 13 E4 B9 47 1D A9 CB 25
AD 60 5C 43 AA 3E 13 42 9B 21 20 11 55 94 5A DC
53 55 5A 8A EA ED 07 A5 9F 2A 76 A8 8F 23 BB 40
E7 9B 94 E5 3F 6C 50 D9 D8 31 21 1E B3 D6 72 BA
FB B0 DC BE BF D5 17 A2 CF 82 42 26 CD C9 07 FA
9C F1 B9 F3 AB 5F CE 20 DB AD BA 37 70 7F 5D 83
77 F8 7B F3 EA 59 E5 CA E7 AD FB 9F 61 B6 05 1E
4B 8B ED 1E 9B 37 0D 42 39 EC 93 17 D7 49 75 0A
04 4A BB 87 68 F9 12 85 C4 9B 7C 18 25 39 0F AE
DB 00 CE C3 9E 22 75 95 4D BE 99 A4 9F BC 1D 3C
74 29 5A 00 47 2D 3D CD 00 36 17 62 B1 2C E9 E5
46 62 D4 70 E3 8C 02 A0 3C A3 4E 75 20 25 84 B6
C1 06 C5 9C 85 E9 B5 45 BB 21 62 AF 27 A0 77 E7
0A DF 14 E7 B5 51 9D 1B C5 8B FE 9A 30 06 FA EF
1A 95 9A 15 38 C2 73 17 B9 C5 9D 92 32 2D 3A AA
C1 86 21 41 5F B9 39 03 23 9A A5 A2 F5 CB 46 84
4B 6E E8 4A D9 5B 62 4B 6D 30 3A EA A8 A0 3F A4
3D 52 B2 18 24 C1 A3 78 18 E7 CE CC 97 85 75 D0
73 9B 53 6E CE 2E EC 66 F0 4D 78 5D DD 85 CF 16
B9 0A 95 C3 12 AD 75 F4 5C C1 48 D6 32 BE F1 5F
C2 5B 0E EC 94 53 22 87 D3 88 A5 F4 E5 74 48 3E
C7 83 91 48 EF D0 45 97 D0 6F E2 6B 8E A2 9B F7
2E 65 87 87 D8 08 93 A7 6C 1B 2D 81 50 98 9A 12
85 A6 C9 D0 16 6B 48 2D C2 90 E7 4A 1B 7B 38 F1
B8 20 42 DA AD B8 76 21 7E A3 05 38 EF 5B 5A 65
00 00 00 00 00 00 00 00 68 00 00 02 01 00 00 00
74 32 2E 30 2E 31 30 30 2E 53 2E 30 32 2E 30 32
37 35 61 30 30 30 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 30 39 50 30 37 00 00 00
''')

s = Stuff()
rv, msg = s.xm_eot()
if rv == s.EOT or msg.find(b'0x03090000'):
    s.rom_cmd('down')
'''
pub struct EfcHeader {
    /* 0x000 */ pub magic: [u8; 4], // 1d 33 47 77
    /* 0x004 */ pub field_0: u8, // always 0. ignored?
    /* 0x005 */ pub fw_type: u8, // 1=efc(only valid when gpio selects efc), 2=eap(only valid when gpio selects eap), 4=(only valid when gpio selects efc), 0x99=weird, small blob. valid in both
    /* 0x006 */ pub field_2: u8, // always 0xff. ignored?
    /* 0x007 */ pub field_3: u8, // 0. ignored?
    /* 0x008 */ pub data_size: u32, // max 0x1dd800 (header_size + data_size <= 0x1e0000)
    /* 0x00C */ pub header_size: u32, // hardcoded to 0x2800 in rom, ignored
    /* 0x010 */ pub key: [u8; 16], // same value for a given chip revision
    /* 0x020 */ pub data_pub_key: [u8; 0x180], // same value for a given chip revision
    /* 0x1A0 */ pub header_sig: [u8; 0x180], // Unknown pub-key.
    /* 0x320 */ pub data_sig: [u8; 0x180],
}
306xxxx: cpu=0x99, when some byte of the hdr is wrong (e.g. magic). xxxx are offending byte values
cpu=0x99 apparently expects payload_len=0x360
cpu=0x99, hdr_len <= 0xa0 has run error 0x30b0000, [0xa1, 0x4a0) has run error 0x6040000, 0x4a0 has run error 0x604001, >= 0x4a1 returns 'C'
so, cpu=0x99 must have payload_len=0x360 and hdr_len set such that data takes up 2 xmodem blocks
getting loaded to 0x01000000

log when it boots from nand:
0x040C0000
0x040C0100
0x040C0200
0x040C0300
0x040C0400
0x040C0500
0x040C0600
0x040C0700
0x040C0800
0x040C0900
0x040C0A00
0x040C0B00
0x040D0000
0x040B0000
0x040B0001
0x010A0000
'''

def make_buf(size):
    words = []
    for i in range(0, size, 4):
        val = 0xccd00000 | (i>>2)
        words.append(val.to_bytes(4, 'little'))
    return b''.join(words)

hdr_len = 0x2800
payload_len = 0 # range 0x400 <= size <= 0x1dd800. error 0x030Axxxx if > 0x1dd800. xxxx is related to amount out of range. < 0x400 results in nothing being read
hdr = struct.pack('<I4B2I', 0x7747331d, 0, 0x99, 0xff, 0, payload_len, hdr_len)
hdr = hdr.ljust(hdr_len, b'A')
fw = hdr + b'\0' * payload_len
#rv = s.xm_send(hdr + b'\0' * payload_len)
fw = Path('C:/src/ps5/CXD90061GG_sb/fcddr_dump_fw_01.bin').read_bytes()[:0x2800+0x177000]
fw = bytearray(fw)
import sys
import os
for i in range(0x100):
    #print(f'{i:x}')
    sys.stdout.flush()
    payload_len = 0x1dd800 # range 0x400 <= size <= 0x1dd800. error 0x030Axxxx if > 0x1dd800. xxxx is related to amount out of range. < 0x400 results in nothing being read
    hdr = struct.pack('<I4B2I', 0x7747331d, 0, 1, 0xff, 0, payload_len, hdr_len)
    total_controlled_len = hdr_len - 0x10 + payload_len
    #hdr = hdr.ljust(hdr_len, b'B')
    #fw = hdr + b'A' * payload_len
    nop_arm = bytes.fromhex('00 00 A0 E1')
    nop_thumb = bytes.fromhex('00 BF')
    nop = nop_arm
    sc = Path('//wsl.localhost/Ubuntu/home/shawn/ps5-uart/efc_glitch_spray').read_bytes()
    pad_dwords = (0x400 - len(sc)) // len(nop)
    block = nop * pad_dwords + sc
    fw = hdr + make_buf(total_controlled_len)

    send_rv = s.xm_send(fw)
    exit()
    run_rv = s.run()
    #if send_rv != (0x3060000 | (payload_len & 0xffff)) and run_rv != 0x6020000 and run_rv != (0x1010000 | i):
    print(f'{i:8x} send: {send_rv:x} run: {run_rv:x}')
    s.rom_cmd('down')
