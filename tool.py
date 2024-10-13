#!/usr/bin/env python3
# import subprocess
# import pyftdi.serialext
import code
import struct
from tqdm import trange
from serial import Serial
from hexdump import hexdump
import sys
from pathlib import Path


def align_down(val, align):
    return val - val % align


def align_up(val, align):
    return align_down(val + align - 1, align)


def all_zero(buf):
    return all(map(lambda x: x == 0, buf))


def load_bin(name):
    return Path(__file__).parent.joinpath(f"bin/{name}.bin").read_bytes()


FW_EFC_FW0 = 1  # efc_ipl
FW_EFC_FW1 = 2  # eap_kbl
FW_PSP_BL = 0x10  # mbr, secldr, kernel
FW_WIFI = 0x12  # blob for wifi/bt dongle
FW_14 = 0x14  # suspiciously unused? but it reads back all zero (at least the "current" nand allocated to it...)
FW_IDATA = 0x15  # idstorage

FW_SIZES = {
    FW_EFC_FW0: 0x0181000,
    FW_EFC_FW1: 0x00B6800,
    FW_PSP_BL: 0x4000000,
    FW_WIFI: 0x0200000,
    FW_14: 0x3A00000,
    FW_IDATA: 0x0200000,
}


class StatusCode:
    kSuccess = 0
    kRxInputTooLong = 0xE0000002
    kRxInvalidChar = 0xE0000003
    kRxInvalidCsum = 0xE0000004
    kUcmdEINVAL = 0xF0000001
    kUcmdUnknownCmd = 0xF0000006
    # SyntheticError (our own codes)
    kEmcInReset = 0xDEAD0000
    kFwConstsVersionFailed = 0xDEAD0001
    kFwConstsVersionUnknown = 0xDEAD0002
    kFwConstInvalid = 0xDEAD0003
    kSetPayloadTooLarge = 0xDEAD0004
    kSetPayloadPuareq1Failed = 0xDEAD0005
    kSetPayloadPuareq2Failed = 0xDEAD0006
    kExploitVersionUnexpected = 0xDEAD0007
    kExploitFailedEmcReset = 0xDEAD0008


class ResultType:
    kTimeout = 0
    kUnknown = 1
    kComment = 2
    kInfo = 3
    kOk = 4
    kNg = 5


class PicoFrame:
    def __init__(self, stream):
        self._type, size = struct.unpack("<BI", stream.read(1 + 4))
        self._status = None
        if self.is_ok_or_ng():
            self._status = struct.unpack("<I", stream.read(4))[0]
            size -= 4
        self._response = str(stream.read(size), "ascii")

    def is_timeout(self):
        return self._type == ResultType.kTimeout

    def is_unknown(self):
        return self._type == ResultType.kUnknown

    def is_comment(self):
        return self._type == ResultType.kComment

    def is_info(self):
        return self._type == ResultType.kInfo

    def is_ok(self):
        return self._type == ResultType.kOk

    def is_ng(self):
        return self._type == ResultType.kNg

    def is_ok_or_ng(self):
        return self.is_ok() or self.is_ng()

    def is_ok_status(self, status):
        return self.is_ok() and self._status == status

    def is_ng_status(self, status):
        return self.is_ng() and self._status == status

    def is_success(self):
        return self.is_ok_status(StatusCode.kSuccess)

    @property
    def rtype(self) -> ResultType:
        return self._type

    @property
    def status(self) -> StatusCode:
        return self._status

    @property
    def response(self) -> str:
        return self._response

    def __repr__(self) -> str:
        if self.is_ok_or_ng():
            r = "OK" if self.is_ok() else "NG"
            return f"{r} {self.status:08X} {self.response}"
        elif self.is_comment():
            return f"# {self.response}"
        elif self.is_info():
            return f"$$ {self.response}"
        elif self.is_unknown():
            return self.response
        return "timeout"


class Ucmd:
    def __init__(self):
        self.port = Serial("COM18", timeout=0.5)

    def wait_frame(self, accept_types, **kwargs) -> list[PicoFrame]:
        response = kwargs.get("response")
        timeout = kwargs.get("timeout")
        if not isinstance(accept_types, tuple):
            accept_types = (accept_types,)
        if timeout is not None:
            timeout_orig = self.port.timeout
            self.port.timeout = timeout
        frames = []
        try:
            while True:
                frame = PicoFrame(self.port)
                # print(frame)
                frames.append(frame)
                if frame.rtype in accept_types and (response is None or response == frame.response):
                    break
        except:
            print("\t\ttimeout")
            pass
        if timeout is not None:
            self.port.timeout = timeout_orig
        return frames

    def cmd_send_recv(self, *args, **kwargs) -> list[PicoFrame]:
        cmdline = " ".join(args)
        self.port.write(bytes(cmdline + "\n", "ascii"))
        self.wait_frame(ResultType.kUnknown, response=cmdline)
        return self.wait_frame((ResultType.kOk, ResultType.kNg), **kwargs)

    def unlock(self):
        return self.cmd_send_recv("unlock", timeout=2)

    def screset(self, val=0):
        # arg gets poked into WDT. if arg is "sc" or "subsys", pokes 0
        return self.cmd_send_recv(f"screset {val}", timeout=5)

    def runseq(self, seq_id):
        return self.cmd_send_recv(f"runseq {seq_id:04X}")

    def gpio_set(self, group: str, num: int, val: int):
        group = group.lower()
        assert group in ("a", "c", "d")
        assert val in (0, 1)
        val = ("clr", "set")[val]
        return self.cmd_send_recv(f"port {val} {group} {num}")

    def gpio_get(self, group: str, num: int):
        group = group.lower()
        assert group in ("a", "c", "d")
        return self.cmd_send_recv(f"port get {group} {num}")

    def pg2_fc_rails_set(self, enable: bool):
        return self.gpio_set("a", 16, 1 if enable else 0)

    def fc_reset_set(self, reset: bool):
        return self.gpio_set("a", 29, 0 if reset else 1)

    def fc_bootmode_set(self, uart: bool):
        return self.gpio_set("a", 30, 1 if uart else 0)

    def fc_cpu_set(self, eap: bool):
        return self.gpio_set("a", 31, 1 if eap else 0)

    def install_custom_cmd(self):
        code = load_bin("emc_cmd_handler")
        ucmd_cec = 0x141458
        assert len(code) <= 0x92C
        self.emc_write(ucmd_cec, code)

    def _custom_cmd(self, cmd: int, *args):
        args = " ".join(map(lambda x: f"{x:x}", args))
        return self.cmd_send_recv(f"cec {cmd:x} {args}")

    def toggle(self, addr: int, val: int, set: bool, delay: int):
        return self._custom_cmd(0, addr, val, set, delay)

    def toggle_fast(self, addr: int, val: int):
        return self._custom_cmd(1, addr, val)

    def titania_spi_init(self):
        # needed or else titania spi reads are bitshifted by 1
        return self._custom_cmd(2)

    # dump |count| lines of 0x7c bytes
    def sflash_dump(self, addr: int, count: int = 1):
        return self._custom_cmd(3, addr, count)

    def sflash_dump_all(self):
        with Path(__file__).with_name("sflash_dump.bin").open("wb") as f:
            num_lines = 0x20
            for i in trange(0, 0x200000, 0x7C * num_lines):
                for frame in self.sflash_dump(i, num_lines):
                    if not frame.is_comment():
                        continue
                    f.write(bytes.fromhex(frame.response))

    def ddr_write_18(self, addr: int, data: bytes):
        assert len(data) <= 4 * 6
        data = data.ljust(4 * 6, b"\0")
        data = [int.from_bytes(data[i : i + 4], "little") for i in range(0, 4 * 6, 4)]
        self._custom_cmd(4, addr, *data)

    def ddr_write(self, addr: int, data: bytes):
        for i in trange(0, len(data), 4 * 6):
            self.ddr_write_18(addr + i, data[i : i + 4 * 6])

    def ddr_write_hook(self, addr: int, match: int, target: int):
        return self._custom_cmd(5, addr, match, target)

    # dies around 36
    def glitch_fc_vcc(self, delay: int):
        # a16 low for given cycles
        return self.toggle(0x5F032420, 0x80, False, delay)

    def glitch_fc_reset(self, delay: int = 1):
        # a29 low for given cycles
        return self.toggle(0x5F032420, 0x100000, False, delay)
        # return self.toggle_fast(0x5F032420, 0x100000)

    # dies around 54
    def glitch_fc_clk0(self, delay: int):
        return self.toggle(0x5F007404, 0x1000, False, delay)

    # dies around 36
    def glitch_fc_clk1(self, delay: int):
        return self.toggle(0x5F007414, 0x40, False, delay)

    def cmd_state_change(self, cmd):
        self.cmd_send_recv(cmd)
        # this is just an attempt to not flood emc. it is ok if it times out
        self.wait_frame(ResultType.kInfo)

    def pg2_on(self):
        self.cmd_state_change("pg2on")

    def pg2_off(self):
        self.cmd_state_change("pg2off")

    def efc_on(self):
        self.cmd_state_change("efcon")

    def efc_off(self):
        self.cmd_state_change("efcoff")

    def eap_on(self):
        self.cmd_state_change("eapon")

    def eap_off(self):
        self.cmd_state_change("eapoff")

    def efc_reset(self):
        self.efc_off()
        self.efc_on()

    def parse_hexdump(self, frames: list[PicoFrame]):
        rv, lines = frames[-1], frames[:-1]
        if not rv.is_ok():
            return None
        data = []
        for l in lines:
            if not l.is_comment():
                continue
            sc_pos = l.response.find(":")
            if sc_pos < 0:
                continue
            for word in l.response[sc_pos + 1 :].split():
                if len(word) != 8:
                    break
                data.append(int(word, 16).to_bytes(4, "little"))
        return b"".join(data)

    def fcddr_read(self, addr, size):
        addr_aligned = align_down(addr, 4)
        offset = addr - addr_aligned
        # because of emc bug, need multiple of 0x10 to get 'OK' on newline
        size_aligned = align_up(offset + size, 0x10)
        data = self.parse_hexdump(self.cmd_send_recv(f"fcddrr {addr_aligned:x} {size_aligned:x}"))
        return data[offset : offset + size]

    def fcddr_read32(self, addr):
        return int.from_bytes(self.fcddr_read(addr, 4), "little")

    def fcddr_write32(self, addr, val):
        # only supports single 32bit write at a time
        self.cmd_send_recv(f"fcddrw {addr:x} {val:x}")

    def fcddr_write(self, addr, data):
        offset = addr & 3
        if offset != 0:
            addr -= offset
            val = self.fcddr_read(addr, offset)
            self.fcddr_write32(addr, int.from_bytes(val + data[: 4 - offset], "little"))
            addr += 4
            data = data[4 - offset :]
        len_aligned = align_down(len(data), 4)
        for i in range(0, len_aligned, 4):
            self.fcddr_write32(addr + i, int.from_bytes(data[i : i + 4], "little"))
        rem = len(data) - len_aligned
        if rem != 0:
            addr += len_aligned
            val = self.fcddr_read(addr + rem, 4 - rem)
            self.fcddr_write32(addr, int.from_bytes(data[len_aligned:] + val, "little"))

    FCDDR_REAL_SIZE = 0x20000000

    def fcddr_alias_read(self, addr: int, size: int):
        return self.fcddr_read(self.FCDDR_REAL_SIZE + addr, size)

    def fcddr_alias_write(self, addr: int, buf: bytes):
        return self.fcddr_write(self.FCDDR_REAL_SIZE + addr, buf)

    def fcddr_addr_to_emc(self, addr: int) -> int:
        return (addr - 0x60000000) & 0xFFFFFFFF

    def emc_read(self, addr: int, size: int) -> bytes:
        return self.fcddr_read(self.fcddr_addr_to_emc(addr), size)

    def emc_write(self, addr: int, buf: bytes):
        self.fcddr_write(self.fcddr_addr_to_emc(addr), buf)

    def emc_or32(self, addr: int, val: int):
        addr = self.fcddr_addr_to_emc(addr)
        self.fcddr_write32(addr, self.fcddr_read32(addr) | val)

    def emc_andn32(self, addr: int, val: int):
        addr = self.fcddr_addr_to_emc(addr)
        self.fcddr_write32(addr, self.fcddr_read32(addr) & ~val)

    VMMIO_TITANIA_SPI = 0x700000
    VMMIO_RT5127 = 0x800000

    def vmmio_r32(self, addr, size):
        return self.parse_hexdump(self.cmd_send_recv(f"r32 {addr:x} {size:x}"))

    def vmmio_w32(self, addr, val):
        return self.parse_hexdump(self.cmd_send_recv(f"w32 {addr:x} {val:x}"))

    def vmmio_r8(self, addr, size):
        return self.parse_hexdump(self.cmd_send_recv(f"r8 {addr:x} {size:x}"))

    def vmmio_w8(self, addr, val):
        if isinstance(val, bytes):
            vals = " ".join(map(lambda x: f"{x:02x}", val))
        elif isinstance(val, int):
            vals = f"{val:02x}"
        return self.parse_hexdump(self.cmd_send_recv(f"w8 {addr:x} {vals}"))

    def titania_pmic_r8(self, reg):
        return self.vmmio_r8(self.VMMIO_RT5127 + reg, 1)

    def titania_pmic_w8(self, reg, val: int):
        return self.vmmio_w8(self.VMMIO_RT5127 + reg, val)

    def spi_read(self, addr, size):
        assert (addr % 4) == 0
        assert (size % 4) == 0
        return self.vmmio_r32(self.VMMIO_TITANIA_SPI + addr, size)

    def spi_read32(self, addr):
        return int.from_bytes(self.spi_read(addr, 4), "little")

    def spi_write32(self, addr, val):
        assert (addr % 4) == 0
        return self.vmmio_w32(self.VMMIO_TITANIA_SPI + addr, val)

    def spi_or32(self, addr, val):
        return self.spi_write32(addr, self.spi_read32(addr) | val)

    def spi_andn32(self, addr, val):
        return self.spi_write32(addr, self.spi_read32(addr) & ~val)

    def spi_sram_keep(self, enable: bool):
        mask = 1 << 24
        addr = 0x9130
        if enable:
            self.spi_or32(addr, mask)
        else:
            self.spi_andn32(addr, mask)

    def efuse_read32(self, index):
        self.spi_write32(0x4004, 1)
        self.spi_write32(0x4008, 0)
        # repeats at index=0x20
        self.spi_write32(0x4010, index)
        self.spi_write32(0x4000, 4 | 1)
        while True:
            if self.spi_read32(0x4004) & 1:
                break
        val = self.spi_read32(0x4014)
        self.spi_write32(0x4004, 1)
        return val

    def spi_soft_reset(self):
        self.spi_andn32(0x9094, 0x40)
        self.spi_or32(0x9094, 1)

        # WCB_DRAIN_REQ, Drain the buffer to DDR
        self.spi_write32(0xA020, 0x1F000002)
        # wait drain
        while True:
            x = self.spi_read32(0xA004)
            # hex-rays garbage
            if (~x & 0xF9FFF) == 0 or (~x & 0xB9FFF) == 0:
                break
            # sleep 1ms

        # SR_REQ=1
        self.spi_write32(0xA020, 0x1F000040)
        # wait self refresh done
        while (self.spi_read32(0xA008) & 4) == 0:
            pass  # sleep 1ms

        # halt the scheduler?
        self.spi_or32(0xA044, 2)

        # WARM_RST_FW=0,WDT_RBOOT_TMR_MAX_VAL=fff
        self.spi_write32(0x9090, 0x0FFF0000)
        # WARM_RST_FW=1,WDT_RBOOT_TMR_MAX_VAL=fff
        self.spi_write32(0x9090, 0x8FFF0000)

    def sccmd(self, cmd, *args, delay=300):
        assert len(args) <= 4
        args = list(args) + [0] * (4 - len(args))
        return self.cmd_send_recv(f"sccmd {cmd} {args[0]:x} {args[1]:x} {args[2]:x} {args[3]:x} {delay}")

    def load_fw(self, fw, to_dram, offset):
        return self.sccmd(1, fw, to_dram, offset)

    def setup_bar(self, mode, size, init_val):
        # mode 0: emc, 1: psp, 2: ?
        return self.sccmd(2, mode, size, init_val)

    def _open_close_nand_access(self, op):
        self.sccmd(5, op)

    def nand_open(self):
        self._open_close_nand_access(0)

    def nand_open_safe(self):
        self._open_close_nand_access(2)

    def nand_close(self):
        self._open_close_nand_access(1)

    def fw1ver(self):
        return self.cmd_send_recv("fw1ver")

    def fw1err(self):
        return self.cmd_send_recv("fw1err")

    def do_seq(self):
        # 16 Main SoC Power ON (Cold Boot)
        seq = [
            0x215D,
            0x203A,
            0x203D,
            0x2126,
            0x2128,
            0x212A,
            0x2135,
            0x211F,
            0x2023,
            0x2125,
            # emc crash for some reason?
            # 0x2121,
            0x2175,
            0x2133,
            0x2167,
            0x2141,
            0x205F,
            0x2123,
            0x2136,
            0x2137,
            0x216D,
            0x2060,
            0x2061,
            0x2025,
        ]
        # 17 Main SoC Reset Release
        seq += [
            0x206B,
            0x2127,
            0x204A,
            # socrtg
            # 0x2129, 0x212f, 0x2169, 0x2161, 0x213c, 0x213d, 0x213f,
            # 0x2050, 0x2083, 0x2155, 0x205c, 0x217f
        ]
        seq += [
            # 0x201b,
        ]
        for s in seq:
            self.runseq(s)

    def unlock_efc(self, use_uart_shell=False):
        # patch emc's titania_ddr_density to make alias
        # this avoids having to actually change the value in nvs(0:0x50)
        self.emc_write(0x13423A, bytes.fromhex("00bf"))

        # powercycle efc so new density is used
        self.pg2_on()
        self.efc_reset()

        # dummy fw load + map to expose ddr4 over pcie
        self.load_fw(FW_WIFI, 1, 0x1000000)
        self.setup_bar(0, 0, 0)

        # deinit magic
        self.spi_write32(0, 0xDEADBEEF)
        if use_uart_shell:
            # We only modify cpu0. The other cores will still be running and
            # write a timeout error to uart ~3 seconds after we take over cpu0.
            # TODO quiesce other stuff.
            self.spi_write32(4, 0x1337)
            self.install_custom_cmd()
            self.ddr_write(0x18000000, load_bin("efc_uart_shell"))

        # patch efc's OpenCloseNandDaccess
        thunk = load_bin("efc_thunk")
        sc_addr = 0x4DBE64
        orig = self.fcddr_alias_read(sc_addr, len(thunk))
        self.fcddr_alias_write(sc_addr, thunk)
        # trigger
        self._open_close_nand_access(0xDEAD)
        # restore - shellcode should disable caches
        self.fcddr_alias_write(sc_addr, orig)

        magic = self.spi_read32(0)
        print(f"{magic:x}")
        return magic == 0x1337

        # nop dram_mem_prot_lock call
        # self.fcddr_alias_write(0x4DBD6C, bytes.fromhex('00bf') * 2)

        # TODO supported way to set this via syspowdown
        # dpkrb_addr = 0x1762CC + 4
        # dpkrb_soft_reset = 0x10
        # dpkrb_sram_keep = 8
        # dpkrb = int.to_bytes(dpkrb_soft_reset | dpkrb_sram_keep, 2, 'little')
        # emc.emc_write(dpkrb_addr, dpkrb)

        # uart0_mute
        # 0x9086D8 1.00 broken console (Samsung)
        # 0x9086F8 3.00 dontstarve console (0A805M3 TOSHIBA)
        #  a0tcm:00008454 CheckSramAddr
        #  dram.text.cpu0:404DB2C9 NvmeCmd_Vsc_92_95_SramReadWrite

        # run eap_kbl
        self.efc_off()
        self.eap_on()


def parse_hexdump(path: Path):
    data = []
    with path.open("r") as f:
        for l in f.readlines():
            l = l.split()
            if l[0] != "m":
                continue
            width = len(l[2]) // 2
            data.extend(map(lambda x: int(x, 16).to_bytes(width, "little"), l[2:]))
    return b"".join(data)


def parse_hexdump2(path: Path):
    data = []
    with path.open("r") as f:
        for l in f.readlines():
            l = l.split()
            if not (l[0] == "#" and l[1][-1] == ":"):
                continue
            width = len(l[2]) // 2
            data.extend(map(lambda x: int(x, 16).to_bytes(width, "little"), l[2:]))
    return b"".join(data)


def hexdump_to_bin(fname):
    path = Path(fname)
    data = parse_hexdump(path)
    path.with_suffix(".bin").open("wb").write(data)


def efc_test():
    # efc = Efc()
    emc = Ucmd()
    # efc.nand_open_safe()
    # efc.cmd('mount')
    # efc.cmd('startcoreactivity')
    # for i in range(0, FW_SIZES[FW_WIFI], 0x1000):
    #    efc.read_mem(0x41000000 + i, 0x1000 // 4, 4)
    # efc.cmd('memset 40004900 ca 100')
    # efc.read_mem(0x40004900, 0x100, 1)
    # efc.cmd('rdpp 00 100 40004900')
    # efc.read_mem(0x10122000, 0x100//4, 4)
    # efc.read_mem(0x10123000, 0x100//4, 4)
    # efc.cmd('VSC_SNEM 1')
    # efc.cmd('VSC_RPP 0 0 0 0 0 0 0 0 0 0')
    # efc.read_mem(0x1000000, 0x100, 4)
    # efc.cmd('getf a7')
    # efc.cmd('seqrw 0 1 0 1')
    # efc.pkg_cfg_auto()
    # for i in range(256): efc.bcm_get_version_info(i << 24)
    # efc.read_mem(0x41000000, 0x200, 1)
    # while True: efc._read_event()
    code.InteractiveConsole(locals=dict(globals(), **locals())).interact("Entering shell...")


def test_efc_on():
    emc = Ucmd()
    emc.screset()
    emc.unlock()
    emc.install_custom_cmd()
    emc.titania_spi_init()
    """
    pg2on
    # [PSQ] [BT WAKE Disabled Start]
    # [PSQ] [GDDR6/NAND Voltage Setting Start]
    # [PSQ] [Titania PMIC Register Initialize Start]
    # [PSQ] [Power Group 2 ON Start]
    # [PSQ] [PCIe Redriver EQ Setting Start]
    # [PSQ] [GPI SW Open Start]
    # [PSQ] [WLAN Module USB Enable Start]
    $$ [MANU] PG2 ON
    # [PSQ] [BT WAKE Enabled Start]
    efcon
    # [PSQ] [10GbE NIC Reset de-assert Start]
    # [PSQ] [SB PCIe initialization EFC Start]
    # [PSQ] [EFC Boot Mode Set Start]
    # [PSQ] [Flash Controller ON EFC Start]
    # [PSQ] [Floyd Reset De-assert Start]
    # [PSQ] [Subsystem PCIe USP Enable Start]
    # [PSQ] [Subsystem PCIe DSP Enable Start]
    # [PSQ] [Flash Controller Initialization EFC Start]
    $$ [MANU] EFC ON
    """
    gddr6_nand_seq = []  # 0x207b,0x207c,0x207d]
    titania_pmic_init = []  # 0x217a]
    pg2_on_seq = []  # 0x200c,0x2109,0x200d,0x2011,0x200e,0x200f,0x2010,0x202e,0x2006]
    sb_pcie_init_efc_seq = []  # 0x201a,0x2030,0x2031]
    # we'll set these gpio ourself, but need 208d to setup ports
    efc_boot_mode_seq = [0x208D]  # ,0x210b,0x210c,0x210d]
    # 201d: 5F007404 |= 0x1000, 5F007414 |= 0x40. both are needed
    # 2089: inits titania spi ports
    fc_on_efc_seq = [
        0x201D,
        # 0x2027,0x2110,0x2033,
        0x2089,
        # 0x2035
    ]
    emc.pg2_fc_rails_set(True)
    # emc.fc_reset_set(True)
    for seq in gddr6_nand_seq:
        emc.runseq(seq)
    for seq in titania_pmic_init:
        emc.runseq(seq)
    for seq in pg2_on_seq:
        emc.runseq(seq)
    for seq in sb_pcie_init_efc_seq:
        emc.runseq(seq)
    for seq in efc_boot_mode_seq:
        emc.runseq(seq)
    emc.fc_bootmode_set(True)
    emc.fc_cpu_set(False)
    for seq in fc_on_efc_seq:
        emc.runseq(seq)
    # some clocks? both pause/resume efc at will
    # emc.emc_or32(0x5F007404, 0x1000)
    # emc.emc_or32(0x5F007414, 0x40)
    emc.fc_reset_set(False)


def console():
    emc = Ucmd()
    # emc.screset()
    # emc.unlock()
    # efc = Efc()
    # assert emc.unlock_efc(True)
    # efc._rx_discard_all()
    # efc.port.write(struct.pack('<2I', 0, 0xdeadbeef))
    # print(efc._read(4).hex())
    code.InteractiveConsole(locals=dict(globals(), **locals())).interact("Entering shell...")


def read_irq_timestamps(efc):
    efc.read_mem(0x9088F0, 0x10 // 4, 4)


# efc.mem_write32(0x10112090, 0xffffffe8 &~ (1<<24))
# will cause ipc timeout -> crash (stopping some cpu clock)


class UcmdContext:
    def __enter__(self):
        self.ctx = Ucmd()
        return self.ctx

    def __exit__(self, exc_type, exc_value, traceback):
        self.ctx.port.close()


class UartContext:
    def __enter__(self):
        import uart_client

        # efc: 230400*2, eap: 230400*3
        self.ctx = uart_client.Client("COM19", 230400*2)
        return self.ctx

    def __exit__(self, exc_type, exc_value, traceback):
        self.ctx.port.close()


if __name__ == "__main__":
    console()
    exit()
    efc = Efc()
    for i in range(0x10):
        sspm = 0x1B200000
        size = 0x100
        efc.dmac_set_addr_zones(0, i)
        efc.dmac_copy(sspm, 0, size)
        efc.mem_read_buf(sspm, size)
    exit()
    emc = Ucmd()
    emc.screset()
    exit()
    if "emc" in sys.argv:
        emc_hax()
    if "efc" in sys.argv:
        efc_hax()
    if len(sys.argv) == 1:
        efc_test()
    if "trig" in sys.argv:
        emc = Ucmd()
        emc.fcddr_read(0x1000000, 0x200)
    if len(sys.argv) > 2 and "conv" == sys.argv[1]:
        hexdump_to_bin(sys.argv[2])
