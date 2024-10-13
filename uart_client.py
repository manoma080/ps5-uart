#!/usr/bin/env python3
import struct, time
import serial
from tqdm import trange
from pathlib import Path

class Reg:
    MIDR = 0
    DBGDRAR = 1
    DBGDSAR = 2
    VBAR = 3
    DBGPRCR = 4
    SCTLR = 5
    CPSR = 6

class Client:
    CMD_PING = 0
    CMD_MEM_ACCESS = 1
    CMD_REG_READ = 2
    CMD_REG_WRITE = 3
    CMD_INT_DISABLE = 4
    CMD_INT_ENABLE = 5
    CMD_DABORT_STATUS = 6

    def __init__(self, port, baudrate=230400):
        self.port = serial.Serial(port, baudrate=baudrate, timeout=1)

    def __del__(self):
        self.port.close()

    def _read_fmt(self, fmt):
        size = struct.calcsize(fmt)
        data = self.port.read(size)
        vals = struct.unpack(fmt, data)
        return vals[0] if len(vals) == 1 else vals

    def _write_fmt(self, fmt, val):
        self.port.write(struct.pack(fmt, val))

    def _read8(self): return self._read_fmt('<B')
    def _read16(self): return self._read_fmt('<H')
    def _read32(self): return self._read_fmt('<I')
    def _write8(self, val): self._write_fmt('<B', val)
    def _write16(self, val): self._write_fmt('<H', val)
    def _write32(self, val): self._write_fmt('<I', val)

    def ping(self):
        magic = 0xa5a5a5a5
        self._write32(self.CMD_PING)
        self._write32(magic)
        return self._read32() == magic + 1

    def _write_mem_access(self, addr, count, stride, is_write):
        data = struct.pack('<2I2B', addr, count, stride, is_write)
        self._write32(self.CMD_MEM_ACCESS)
        self.port.write(data)

    def cp_reg_read(self, reg):
        self._write32(self.CMD_REG_READ)
        self._write8(reg)
        return self._read32()

    def cp_reg_write(self, reg, val):
        self._write32(self.CMD_REG_WRITE)
        self._write8(reg)
        self._write32(val)

    def int_disable(self):
        self._write32(self.CMD_INT_DISABLE)

    def int_enable(self):
        self._write32(self.CMD_INT_ENABLE)

    def dabort_status(self):
        self._write32(self.CMD_DABORT_STATUS)
        addr, status = self._read_fmt('<II')
        if addr == 0xffffffff and status == 0xffffffff: return None
        return addr, status

    def check_dabort(self):
        dabort = self.dabort_status()
        if dabort is None:
            return
        dfar = dabort[0]
        dfsr = dabort[1]
        access = 'w' if (dfsr >> 11) & 1 else 'r'
        src = ((dfsr >> 6) & 0x10) | (dfsr & 0xf)
        src_name = {
            0b00001: 'align',
            0b00000: 'background',
            0b01101: 'perm',
            0b00010: 'debug',
            0b01000: 'sync ext',
            0b11001: 'sync parity',
            0b10110: 'async ext',
            0b11000: 'async parity',
        }.get(src, 'unknown')
        print(f'DABORT {dfar:08x} {dfsr:08x} {access} {src_name}')

    def debug_reset(self):
        self.cp_reg_write(Reg.DBGPRCR, 2)

    def set_breakpoint(self, index, addr):
        # XXX these addrs are for EAP. EFC has debug in nearby addrspace.
        # DBGBCRn clear
        self.write32(0x18130000 + 0x140 + index * 4, 0)
        # DBGBVRn
        self.write32(0x18130000 + 0x100 + index * 4, addr & ~0b11)
        # DBGBCRn
        BT = 0b0000
        BAS = 0b1111
        self.write32(0x18130000 + 0x140 + index * 4, (BT << 20) | (BAS << 5) | 1)

    def read_fmt(self, addr, fmt):
        size = struct.calcsize(fmt)
        self._write_mem_access(addr, 1, size, 0)
        val = self._read_fmt(fmt)
        #self.check_dabort()
        return val

    def read_array_fmt(self, addr, fmt, size):
        stride = struct.calcsize(fmt)
        count = size//stride
        self._write_mem_access(addr, count, stride, 0)
        for _ in range(count):
            yield addr, self._read_fmt(fmt)
            addr += stride

    def read_regs32(self, addr, count):
        return [val for addr, val in self.read_array_fmt(addr, '<I', 4 * count)]

    def read_regs32_str(self, addr, count):
        return ' '.join([f'{val:8x}' for val in self.read_regs32(addr, count)])

    def write_fmt(self, addr, fmt, val):
        size = struct.calcsize(fmt)
        self._write_mem_access(addr, 1, size, 1)
        self._write_fmt(fmt, val)
        #self.check_dabort()

    def write_array_fmt(self, addr, fmt, vals):
        stride = struct.calcsize(fmt)
        assert stride in (1,2,4)
        if isinstance(vals, bytes):
            old = vals
            vals = []
            for i in range(0, len(old), stride):
                vals.append(struct.unpack_from('<I', old, i)[0])
        self._write_mem_access(addr, len(vals), stride, 1)
        for val in vals: self._write_fmt(fmt, val)
        #self.check_dabort()

    def read8(self, addr): return self.read_fmt(addr, '<B')
    #def read16(self, addr): return self.read_fmt(addr, '<H')
    def read32(self, addr): return self.read_fmt(addr, '<I')
    def write8(self, addr, val): self.write_fmt(addr, '<B', val)
    #def write16(self, addr, val): self.write_fmt(addr, '<H', val)
    def write32(self, addr, val): self.write_fmt(addr, '<I', val)

    def read(self, addr, size):
        self._write_mem_access(addr, size, 1, 0)
        data = self.port.read(size)
        assert len(data) == size
        return data

    def write(self, addr, data):
        self._write_mem_access(addr, len(data), 1, 1)
        self.port.write(data)

    def read_str(self, addr):
        data = []
        while True:
            val = self.read8(addr)
            if val == 0: break
            data.append(val)
            addr += 1
        return str(bytes(data), 'ascii')

    def wait_server_up(self):
        while True:
            self.port.flushInput()
            self.port.flushOutput()
            try:
                if self.ping(): break
                time.sleep(.2)
            except: pass

    def reinstall_hax(self):
        self.write(0x58800000,
            struct.pack('<2I', 0x58800000 + 4 * 2 + 0x1c, 0x0000D274) +
            struct.pack('<9I', 4, 0xB0AC, 0xC50078, 7, 8, 9, 10, 0x58800000 + 4 * (2 + 9 * 1) + 0x1c, 0x0000D274) +
            struct.pack('<9I', 4, 0xA344, 6, 7, 8, 9, 10, 0x58800000 + 4 * (2 + 9 * 2) + 0x1c, 0x0000D274) +
            struct.pack('<9I', 4, 0x58000000, 6, 7, 8, 9, 10, 0x58800000 + 4 * (2 + 9 * 3) + 0x1c, 0x0000D274)
            )

    def fill_mem(self):
        def make_buf(offset, size):
            return b''.join([(0xaab00000 + offset + x).to_bytes(4, 'little') for x in range(size//4)])
        chunk_len = 0x1000
        for i in trange(0, 0x1e0000, chunk_len):
            self.write(i, make_buf(i, chunk_len))

    def dump_mem(self):
        with Path('sram_after_eap_reset.bin').open('wb') as f:
            chunk_len = 0x1000
            for i in trange(0, 0x1e0000, chunk_len):
                f.write(self.read(i, chunk_len))
