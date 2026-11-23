#!/usr/bin/env python3
"""Canon imageFORMULA R10 userspace driver for Linux (stdlib only).

How the device works (reverse engineered from CaptureOnTouch Lite Launcher):

The scanner exposes a FAT volume "ONTOUCHLITE" containing two 2 MiB files the
firmware intercepts at the block level:

  TRANSFER.dat  command / status / data-out window
  INDATA.dat    data-in window

A SCSI-style command is wrapped in the same 12-byte framing the SANE canon_dr
backend uses for Canon USB scanners and written to TRANSFER.dat:

  off 0   24-byte command packet  00 00 00 14 | 00 01 90 00 | 00 00 00 00 | CDB (12, zero padded)
  off 24  4-byte status word      host writes FF FF FF FF, device replaces it (0 = good)
  off 28  data-out packet         BE(len+8) | 00 02 b0 00 | 00 00 00 00 | data

The host then polls offset 24 until it is no longer FFFFFFFF (100 ms interval).
Data-in is then read from INDATA.dat offset 0. Non-zero status -> REQUEST SENSE.
Everything is done with page-cache bypass (O_DIRECT here, F_NOCACHE on macOS).
"""
import argparse
import math
import mmap
import os
import struct
import sys
import time

SECTOR = 512
WINDOW = 0x200000                     # CmdFileSize
STATUS_OFF = 24
DATAOUT_OFF = 28
# opcodes the vendor code does not poll status for after the command packet
# (they are followed by a data-out phase or are fire-and-forget)
NO_WAIT_OPS = {0x15, 0x1B, 0x24, 0x2A, 0xD6, 0xE1}
APP_START_ADDRESS = 0x10700000        # TOUCHDRL.ini StartAddress


class ScannerError(Exception):
    pass


# Sense codes -> messages, from CCanoDR::DecodeSense and CCanoDRDS::ShowAlert
# (R10Lite.ds) plus the English Localizable.strings. Key: (sense key, ASC, ASCQ);
# None as ASC/ASCQ matches any value.
SENSE_MESSAGES = [
    ((3, 0x3A, 0x00), "no paper in the feeder", "load a sheet"),
    ((3, 0x80, 0x00), "paper jam", "open the cover, remove the paper, close the cover"),
    ((3, 0x80, 0x01), "scanner cover is open", "close the cover"),
    ((3, 0x81, 0x01), "double feed detected", "check the document and scan it again"),
    ((3, 0x60, 0x00), "lamp error", "power-cycle the scanner"),
    ((3, None, None), "unknown device error", "power-cycle the scanner"),
    ((2, None, None), "scanner not ready", "try again"),
    ((4, None, None), "scanner hardware error", "power-cycle the scanner; contact service if it persists"),
    ((5, 0x2C, 0x00), "command sequence error", "the scanner was not expecting this command; try again"),
    ((5, 0x55, 0x00), "scanner out of memory", "try a lower resolution"),
    ((5, 0x3A, 0x00), "no paper in the feeder", "load a sheet"),
    ((5, 0x1A, 0x00), "invalid parameter (parameter list length)", "unsupported setting combination"),
    ((5, None, None), "illegal request", "unsupported command or setting"),
    ((6, 0x29, 0x00), "power-on reset (unit attention)", "retry; the scanner was reset or reconnected"),
    ((0x0B, 0x80, 0x00), "scanner timed out", "check the paper feeder"),
]


def describe_sense(key, asc, ascq):
    """(message, advice) for a sense triple, or (None, None) for no error."""
    if key == 0:
        return None, None
    for (k, a, q), msg, adv in SENSE_MESSAGES:
        if k == key and a in (None, asc) and q in (None, ascq):
            return msg, adv
    return "unknown error (sense %x/%02x%02x)" % (key, asc, ascq), "power-cycle the scanner"


class DeviceError(ScannerError):
    """A command failed with CHECK CONDITION; carries the decoded sense."""
    def __init__(self, op, key, asc, ascq, raw):
        self.key, self.asc, self.ascq, self.raw = key, asc, ascq, raw
        msg, adv = describe_sense(key, asc, ascq)
        super().__init__("%s (sense %x/%02x %02x, command %02x)%s"
                         % (msg, key, asc, ascq, op, " - " + adv if adv else ""))


def _align(n):
    return (n + SECTOR - 1) // SECTOR * SECTOR


def _mounts():
    """[(device, mountpoint, options)] from /proc/mounts."""
    out = []
    with open("/proc/mounts") as f:
        for line in f:
            dev, mnt, _, opts = line.split()[:4]
            out.append((dev, mnt.replace("\\040", " "), opts.split(",")))
    return out


def _is_r10_volume(mnt):
    try:
        names = {n.lower() for n in os.listdir(mnt)}
    except OSError:
        return False
    return {"transfer.dat", "indata.dat"} <= names


def find_r10_partitions():
    """Block devices of attached R10s: the first partition of each whole disk
    whose USB vendor/model is CANON / R10 (the vfat ONTOUCHLITE LUN)."""
    parts = []
    try:
        disks = sorted(os.listdir("/sys/block"))
    except OSError:
        return parts
    for d in disks:
        base = "/sys/block/%s/device/" % d
        try:
            vendor = open(base + "vendor").read().strip()
            model = open(base + "model").read().strip()
        except OSError:
            continue
        if vendor.upper() != "CANON" or not model.upper().startswith("R10"):
            continue
        for p in sorted(os.listdir("/sys/block/" + d)):
            if p.startswith(d) and os.path.exists("/dev/" + p):
                parts.append("/dev/" + p)
    return parts


def _udisks(*args):
    import shutil
    import subprocess
    exe = shutil.which("udisksctl")
    if not exe:
        raise ScannerError("udisksctl not found; mount the R10 volume by hand")
    r = subprocess.run([exe] + list(args) + ["--no-user-interaction"],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return r.returncode, (r.stdout + r.stderr).strip()


def find_volume(wait=10.0, log=None):
    """Mount point of the R10's ONTOUCHLITE volume. If the scanner is attached
    but the volume isn't mounted (or is mounted read-only), mount it read-write
    with udisksctl (no root needed). Waits up to `wait` s for a just-plugged
    scanner to appear."""
    say = log or (lambda m: print(m, file=sys.stderr))
    t0 = time.time()
    while True:
        for dev, mnt, opts in _mounts():
            if _is_r10_volume(mnt):
                if "ro" not in opts:
                    return mnt
                say("R10 volume %s is mounted read-only; remounting read-write" % mnt)
                _udisks("unmount", "-b", dev)
                break
        parts = find_r10_partitions()
        mounted = {dev for dev, _, _ in _mounts()}
        for dev in parts:
            if dev in mounted:
                continue                      # e.g. the Mac HFS+ LUN, or not ours
            rc, msg = _udisks("mount", "-b", dev, "-o", "rw")
            if rc == 0:
                say(msg)
                for d, mnt, opts in _mounts():
                    if d == dev and _is_r10_volume(mnt):
                        return mnt
            elif "already mounted" not in msg.lower() and dev.endswith("1"):
                say("could not mount %s: %s" % (dev, msg))
        if time.time() - t0 >= wait:
            break
        time.sleep(1.0)
    if not parts:
        raise ScannerError("no Canon R10 found (is it plugged in and switched on?)")
    raise ScannerError(
        "R10 found (%s) but its volume could not be mounted read-write. Try:\n"
        "  udisksctl mount -b %s" % (", ".join(parts), parts[0]))


def _real_name(directory, name):
    for n in os.listdir(directory):
        if n.lower() == name.lower():
            return os.path.join(directory, n)
    raise ScannerError("%s not found in %s" % (name, directory))


class FileTransport:
    """Tunnels commands through TRANSFER.dat / INDATA.dat."""

    def __init__(self, volume=None, timeout=90.0, verbose=False):
        self.volume = volume or find_volume()
        self.timeout = timeout
        self.verbose = verbose
        flags = os.O_RDWR | os.O_DIRECT | os.O_SYNC
        try:
            self.fd_in = os.open(_real_name(self.volume, "INDATA.dat"), flags)
            self.fd_tx = os.open(_real_name(self.volume, "TRANSFER.dat"), flags)
        except PermissionError:
            raise ScannerError("cannot open the .dat files read-write; is the "
                               "volume mounted read-only?")
        self.buf = mmap.mmap(-1, WINDOW)          # page aligned for O_DIRECT
        self.status = 0
        # session start, as the vendor code does: zero the whole data-in window
        self._pwrite(self.fd_in, 0, bytes(WINDOW))

    def close(self):
        if self.fd_tx is not None:
            # vendor CloseSession writes a 512-byte block of zeros to TRANSFER.dat
            self._pwrite(self.fd_tx, 0, bytes(SECTOR))
            os.close(self.fd_tx)
            os.close(self.fd_in)
            self.fd_tx = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # --- aligned I/O -----------------------------------------------------
    def _pread(self, fd, off, n):
        size = _align(n)
        mv = memoryview(self.buf)[:size]
        got = os.preadv(fd, [mv], off)
        if got < n:
            raise ScannerError("short read %d < %d" % (got, n))
        return bytes(mv[:n])

    def _pwrite(self, fd, off, data):
        assert off % SECTOR == 0
        size = _align(len(data))
        self.buf[:len(data)] = data
        self.buf[len(data):size] = bytes(size - len(data))
        os.pwritev(fd, [memoryview(self.buf)[:size]], off)

    def _patch(self, off, data):
        """Read-modify-write bytes at an unaligned offset of TRANSFER.dat."""
        start = off // SECTOR * SECTOR
        end = _align(off + len(data))
        blk = bytearray(self._pread(self.fd_tx, start, end - start))
        blk[off - start:off - start + len(data)] = data
        self._pwrite(self.fd_tx, start, blk)

    # --- protocol --------------------------------------------------------
    def _wait_status(self):
        self._patch(STATUS_OFF, b"\xff\xff\xff\xff")
        deadline = time.monotonic() + self.timeout
        while True:
            st = struct.unpack(">I", self._pread(self.fd_tx, 0, SECTOR)[STATUS_OFF:STATUS_OFF + 4])[0]
            if st != 0xFFFFFFFF:
                self.status = st
                return st
            if time.monotonic() > deadline:
                raise ScannerError("timeout waiting for scanner status")
            time.sleep(0.1)

    def _send_cdb(self, cdb):
        pkt = bytearray(24)
        pkt[0:12] = bytes.fromhex("00000014 00019000 00000000")
        pkt[12:12 + len(cdb)] = cdb
        if self.verbose:
            print("> cdb %s" % bytes(cdb).hex(" "), file=sys.stderr)
        self._patch(0, pkt)

    def execute(self, cdb, data_out=None, data_in_len=0, check=True, retries=2):
        """Run one command. Returns data-in bytes (or b''). Retries on UNIT ATTENTION."""
        for attempt in range(retries + 1):
            try:
                return self._execute(cdb, data_out, data_in_len, check)
            except ScannerError as e:
                if attempt == retries or getattr(e, "key", None) != 6:
                    raise
                if self.verbose:
                    print("unit attention, retrying", file=sys.stderr)

    def _execute(self, cdb, data_out, data_in_len, check):
        cdb = bytes(cdb)
        self._send_cdb(cdb)
        if data_out is not None:
            hdr = struct.pack(">I", len(data_out) + 8) + bytes.fromhex("0002b000 00000000")
            self._patch(DATAOUT_OFF, hdr + bytes(data_out))
            st = self._wait_status()
        elif cdb[0] in NO_WAIT_OPS:
            return b""
        else:
            st = self._wait_status()
        if self.verbose:
            print("< status %08x" % st, file=sys.stderr)
        data = b""
        if data_in_len:
            data = self._pread(self.fd_in, 0, data_in_len)
        if st and check:
            key, asc, ascq, _, raw = self.sense()
            raise DeviceError(cdb[0], key, asc, ascq, raw)
        return data

    def sense(self):
        """REQUEST SENSE -> (key, asc, ascq, info-if-ILI, raw)."""
        s = self.execute(bytes([0x03, 0, 0, 0, 14, 0]), data_in_len=14, check=False)
        info = struct.unpack(">I", s[3:7])[0] if s[2] & 0x20 else 0
        return s[2] & 0xF, s[12], s[13], info, s

    def request_sense(self):
        key, asc, ascq, info, s = self.sense()
        return "key=%x asc=%02x ascq=%02x ili_info=%d raw=%s" % (key, asc, ascq, info, s.hex())


class R10:
    def __init__(self, transport):
        self.t = transport

    def inquiry(self, n=96):
        return self.t.execute(bytes([0x12, 0, 0, 0, n, 0]), data_in_len=n)

    def read_buffer(self, addr, length):
        """Canon READ BUFFER variant: 32-bit address, 24-bit length."""
        assert length <= 0xFFFFFF
        cdb = bytes([0x3B, 0]) + struct.pack(">I", addr) + struct.pack(">I", length)[1:] + b"\0"
        return self.t.execute(cdb, data_in_len=length)

    def app_files(self, start=APP_START_ADDRESS):
        hdr = self.read_buffer(start, 0x100)
        count = struct.unpack(">H", hdr[:2])[0]
        if count > 31:
            raise ScannerError("bad archive header: %s" % hdr[:32].hex())
        return [struct.unpack_from(">II", hdr, 2 + 8 * i) for i in range(count)]

    def read_blob(self, addr, size, chunk=0x100000):
        out = bytearray()
        while size:
            n = min(chunk, size)
            out += self.read_buffer(addr, n)
            addr += n
            size -= n
        return bytes(out)


    # ---- scanning (canon_dr-style command set, from CCanoDR in R10Lite.ds) ----
    def inquiry_ex(self):
        d = self.t.execute(bytes.fromhex("1201f0003000"), data_in_len=0x30)
        c = {"base_xres": struct.unpack_from(">H", d, 5)[0],
             "base_yres": struct.unpack_from(">H", d, 7)[0],
             "max_width": struct.unpack_from(">I", d, 20)[0],
             "max_length": struct.unpack_from(">I", d, 24)[0],
             "raw": d.hex()}
        c["width_1200"] = c["max_width"] * 1200 // c["base_xres"]
        return c

    def read(self, dtc_index, length, check=True):
        """READ(10) with the driver's data-type table (index 0 = image)."""
        dtc = [0x00, 0x80, 0x80, 0x80, 0x84, 0x8B, 0x8C, 0x8C, 0xA1] + [0x91] * 7
        q = [b"\0\0", b"\0\0", b"\0\4", b"\0\1", b"\0\0", b"\0\0", b"\0\0", b"\0\1",
             b"\0\0", b"\7\0", b"\x09\0", b"\x0a\0", b"\x0c\0", b"\x23\0", b"\x25\0", b"\x26\0"]
        cdb = bytes([0x28, 0, dtc[dtc_index], 0]) + q[dtc_index] + struct.pack(">I", length)[1:] + b"\0"
        return self.t.execute(cdb, data_in_len=length, check=check)

    def document_ready(self):
        return self.read(5, 1)[0]

    def button_down(self):
        """Operation-panel key state (vendor "OperationpanelEZKeyStatus"):
        READ dtc 0x84, 8 bytes; byte0 bit7 is the R10's button, set only while
        it is held (not latched), so poll at <= 100 ms. The vendor also maps
        bits 6 and 2 to keys 2 and 3 (unused on the R10)."""
        return bool(self.read(4, 8)[0] & 0x80)

    def wait_button(self, timeout=None, poll=0.08):
        """Block until the button is pressed and released. False on timeout."""
        t0 = time.time()
        while not self.button_down():
            if timeout is not None and time.time() - t0 > timeout:
                return False
            time.sleep(poll)
        while self.button_down():
            time.sleep(poll)
        return True

    def set_window(self, wid, xres, yres, ulx, uly, width, length, composition, bpp=8):
        desc = bytearray(44)
        desc[0] = wid
        struct.pack_into(">HHIIII", desc, 2, xres, yres, ulx, uly, width, length)
        desc[25] = composition          # 2 = gray, 5 = RGB
        desc[26] = bpp
        desc[29] = 0x10
        data = bytes(6) + struct.pack(">H", len(desc)) + desc
        self.t.execute(bytes([0x24, 0, 0, 0, 0, 0, 0, 0, len(data), 0]), data_out=data)

    def define_scan_mode(self, page, body):
        data = bytearray(20)
        data[4] = page
        data[5] = 0x0E
        data[6:6 + len(body)] = body
        self.t.execute(bytes([0xD6, 0x10, 0, 0, len(data), 0]), data_out=bytes(data))

    def scan(self, ids):
        self.t.execute(bytes([0x1B, 0, 0, 0, len(ids), 0]), data_out=bytes(ids))

    def object_position(self, action):
        """0 = unload/eject, 1 = load (from driver: 0x40100 >> (action*8))."""
        self.t.execute(bytes([0x31, (0x40100 >> (action * 8)) & 0xFF, 0, 0, 0, 0, 0, 0, 0, 0]))

    def page_info(self):
        """After a sheet: what the vendor driver reads (READ dtc 0x80 q 00 04 /
        00 00 / 00 01, 16 bytes each). Units 1/1200 inch."""
        q = lambda t: struct.unpack(">4i", self.read(t, 0x10))
        size, window, offs = q(2), q(1), q(3)
        return {"paper_length": size[3], "window": window, "offsets": offs}

    def read_page(self, chunk=0x100000, log=None):
        """READ image until CHECK CONDITION. Returns (bytes, sense tuple)."""
        out = bytearray()
        while True:
            data = self.read(0, chunk, check=False)
            if self.t.status == 0:
                out += data
                if log:
                    log("  read %d (total %d)" % (len(data), len(out)))
                continue
            sense = self.t.sense()
            key, asc, ascq, info, raw = sense
            got = chunk - info if raw[2] & 0x20 else 0
            out += data[:got]
            if log:
                log("  end: sense key=%x asc=%02x ascq=%02x residue=%d -> +%d (total %d) raw=%s"
                    % (key, asc, ascq, info, got, len(out), raw.hex()))
            return bytes(out), sense


# ---- calibration (port of CCanoDR::AdjustLight + DRHachi::CAdjustLight) -----
def cdiv(a, b):
    """C-style integer division (truncate toward zero)."""
    q = abs(a) // abs(b)
    return q if (a >= 0) == (b >= 0) else -q


def clamp(v, lo, hi):
    return lo if v < lo else hi if v > hi else v


def unpack12(buf, n):
    """12-bit little-endian packed (2 px / 3 bytes) -> list of n ints."""
    out = [0] * n
    j = 0
    for i in range(0, n - 1, 2):
        b0, b1, b2 = buf[j], buf[j + 1], buf[j + 2]
        out[i] = b0 | (b1 & 0xF) << 8
        out[i + 1] = b1 >> 4 | b2 << 4
        j += 3
    if n & 1:
        out[n - 1] = buf[j] | (buf[j + 1] & 0xF) << 8
    return out


GAIN_TARGET = 2730            # LIGHT_ADJUST_GAIN_ADJ_TARGET_LIST[0]
SHADING_TARGET_GRAY = 4316    # CShading::makeShadingData::target
SHADING_TARGET_RGB = (4306, 4317, 4349)


class Calibrator:
    """Reproduces the vendor light adjustment. Works on per-side lists of
    planes (each plane = one averaged line of 12-bit values)."""

    def __init__(self, r, width_1200, dpi, color, sides, side_mode, log):
        if dpi not in (300, 600):
            raise ScannerError("calibration supports 300 or 600 dpi only")
        self.r, self.w1200, self.dpi, self.color = r, width_1200, dpi, color
        self.sides, self.side_mode, self.log = sides, side_mode, log
        self.gain = [[0] * 3 for _ in range(2)]
        self.offset = [[0x80] * 3 for _ in range(2)]
        self.exp = [[0] * 3 for _ in range(2)]
        self.ids = (0xFF, 0xFF)
        self.state = 0
        self.levels = {}

    # -- device I/O --------------------------------------------------------
    def set_adjust_data(self):
        data = b""
        for s in range(2):
            data += bytes(self.gain[s]) + b"\0" + bytes(self.offset[s]) + b"\0"
            data += struct.pack(">HHH", *[clamp(e, 0, 0xFFFF) for e in self.exp[s]]) + bytes(6)
        self.r.t.execute(bytes([0xE1, 0, 0, 0, 0, 3, 0, 0, len(data), 0]), data_out=data)

    def ref_scan(self, comp, set_adjust=True):
        """One 8-line 12-bit reference scan -> [side][plane] averaged lines."""
        r = self.r
        if set_adjust:
            self.set_adjust_data()
        for wid in range(self.sides):
            r.set_window(wid, self.dpi, self.dpi, 0, 0, self.w1200, 9600 // self.dpi, comp, bpp=12)
        r.define_scan_mode(0x32, bytes([self.side_mode, 1]))
        r.define_scan_mode(0x36, b"")
        r.scan(list(self.ids[:self.sides]))
        w = self.w1200 * self.dpi // 1200
        wt = w * self.sides
        rowbytes = ((12 * wt >> 3) + 1) & ~1
        planes = 3 if comp == 5 else 1
        lines = 8
        raw = r.read(0, planes * rowbytes * lines)
        r.object_position(0)
        acc = [[0] * wt for _ in range(planes)]
        for y in range(lines):
            for p in range(planes):
                off = (y * planes + p) * rowbytes
                for i, v in enumerate(unpack12(raw[off:off + rowbytes], wt)):
                    acc[p][i] += v
        avg = [[v // lines for v in plane] for plane in acc]
        # duplex: pixel interleaved, even = side A (window 0), odd = side B
        return [[plane[s::self.sides] for plane in avg] for s in range(self.sides)]

    # -- algorithm ------------------------------------------------------------
    def _set_all_exp(self, v):
        self.exp = [[v] * 3 for _ in range(2)]

    def _offset(self, img):
        for s in range(self.sides):
            mn = min(min(pl) for pl in img[s])
            g = self.gain[s][0]
            o = self.offset[s][0] - int((0x4F - g) * (mn - 0x60) * (1 / 4096) * 1980 / 150.48)
            self.offset[s] = [clamp(o, 0, 255)] * 3
            self.log("  side %d: dark min %d -> offset %d" % (s, mn, self.offset[s][0]))

    def _gain(self, img):
        for s in range(self.sides):
            mx = max(max(pl) for pl in img[s])
            g = 0x4F - int((0x4F - self.gain[s][0]) * (mx / GAIN_TARGET))
            self.gain[s] = [clamp(g, 0, 255)] * 3
            self.log("  side %d: white max %d -> gain %d" % (s, mx, self.gain[s][0]))

    def _record(self, name, img):
        self.levels[name] = {"exp": list(self.exp[0]),
                             "max": [[max(pl) for pl in img[s]] for s in range(self.sides)],
                             "min": [[min(pl) for pl in img[s]] for s in range(self.sides)]}
        self.log("  %s @%s: max %s min %s" % (name, self.exp[0], self.levels[name]["max"],
                                              self.levels[name]["min"]))

    def _decide(self):
        D, S, L, A = (self.levels[k] for k in ("dark", "sat", "low", "adj"))
        rate = 95 if self.color else 31
        cap = int(GAIN_TARGET * 0.95)
        lim_a, lim_b = (2500, 3000) if self.dpi == 300 else (5000, 6000)
        for s in range(self.sides):
            satmin = min(S["max"][s])
            darkmax = max(D["min"][s])
            T = min(cdiv((satmin - darkmax) * rate, 100) + darkmax, cap)
            e = []
            for c in range(3):
                e1, m1 = L["exp"][c], L["max"][s][c]
                e2, m2 = A["exp"][c], A["max"][s][c]
                if m1 == m2:
                    e.append(0)
                else:
                    e.append(cdiv(e1 * m2 - e2 * m1, m2 - m1) + cdiv((e1 - e2) * T, m1 - m2))
            lv, lim = e[0], lim_a
            if e[0] / lim_a < e[1] / lim_b:
                lv, lim = e[1], lim_b
            if lv / lim < e[2] / lim_b:
                lv, lim = e[2], lim_b
            if lim < lv:
                e = [cdiv(lim * x, lv) for x in e]
            self.exp[s] = [clamp(x, 0, 0x1FFF) for x in e]
            self.log("  side %d: target %d -> LED exposure R/G/B %s" % (s, T, self.exp[s]))

    def run(self):
        comp_mode = 5 if self.color else 2
        e0 = 1500 if self.dpi == 300 else 3500
        it = 0
        while True:
            comp = 5 if 1 <= it <= 4 else comp_mode
            img = self.ref_scan(comp)
            st = self.state
            self.state += 1
            if st == 0:
                self._offset(img)
                self._set_all_exp(0)
                self.ids = (0xFE, 0xFE)
            elif st == 1:
                self._record("dark", img)
                self._set_all_exp(0x1FFF)
            elif st == 2:
                self._record("sat", img)
                self._set_all_exp(200)
            elif st == 3:
                self._record("low", img)
                self._set_all_exp(e0)
            elif st == 4:
                self._record("adj", img)
                self._decide()
            elif st == 5:
                self._gain(img)
                self.ids = (0xFF, 0xFF)
            elif st == 6:
                self._offset(img)
                break
            it += 1
        self.ids = (0xFE, 0xFE)
        self.white = self.ref_scan(comp_mode)
        self.ids = (0xFF, 0xFF)
        self.black = self.ref_scan(comp_mode, set_adjust=False)
        return self.shading(self.white, self.black)

    # -- cache ----------------------------------------------------------------
    def to_dict(self):
        return {"gain": self.gain, "offset": self.offset, "exp": self.exp,
                "white": self.white, "black": self.black}

    def restore(self, d):
        """Re-apply a cached calibration: send its register values, rebuild LUTs."""
        self.gain, self.offset, self.exp = d["gain"], d["offset"], d["exp"]
        self.white, self.black = d["white"], d["black"]
        self.set_adjust_data()
        return self.shading(self.white, self.black)

    curves = None                     # factory light curves, set by the caller

    def shading(self, white, black):
        """-> [side][plane] list of per-column 256-byte LUTs."""
        targets = SHADING_TARGET_RGB if self.color else (SHADING_TARGET_GRAY,)
        out = []
        white = [list(p) for p in white]
        if self.curves:
            nplanes = 3 if self.color else 1
            for s in range(self.sides):
                rec = self.curves.get((s, nplanes, self.dpi))
                if rec is None:
                    self.log("  side %d: no factory light curve" % s)
                    continue
                div, curve = rec
                for p in range(nplanes):
                    white[s][p] = apply_light_curve(white[s][p], black[s][p], div, curve[p])
                self.log("  side %d: factory light curve applied (mean x%.3f)"
                         % (s, sum(curve[0]) / len(curve[0]) / div))
        for s in range(self.sides):
            planes = []
            for p, T in enumerate(targets):
                cache, luts = {}, []
                for wv, bv in zip(white[s][p], black[s][p]):
                    diff = wv - bv if wv > bv else 0
                    coef = (T << 12) // diff if diff and diff * 16 > T else 0xFFFF
                    key = (bv >> 4, coef)
                    if key not in cache:
                        b8 = key[0]
                        cache[key] = bytes(min(255, (max(v - b8, 0) * coef) >> 12) for v in range(256))
                    luts.append(cache[key])
                planes.append(luts)
                self.log("  side %d plane %d: white %d..%d black %d..%d" % (
                    s, p, min(white[s][p]), max(white[s][p]), min(black[s][p]), max(black[s][p])))
            out.append(planes)
        return out


def apply_luts(img, w, luts):
    out = bytearray(len(img))
    for x in range(w):
        out[x::w] = img[x::w].translate(luts[x])
    return bytes(out)


def shift_rows(img, w, h, f):
    """Resample a plane vertically by f lines (|f| <= 1), linear interpolation.
    new[y] = (1-|f|)*P[y] + |f|*P[y+sign(f)]. Uses translate + big-int lane
    addition so it stays fast without numpy (the two terms never exceed 255)."""
    if not f or h < 2:
        return img
    a = abs(f)
    ta = bytes(int((1 - a) * v) for v in range(256))
    tb = bytes(int(a * v + 0.5) for v in range(256))
    d = 1 if f > 0 else -1
    out = bytearray(img)
    rng = range(0, h - 1) if d > 0 else range(1, h)
    for y in rng:
        p = img[y * w:(y + 1) * w].translate(ta)
        q = img[(y + d) * w:(y + d + 1) * w].translate(tb)
        out[y * w:(y + 1) * w] = (int.from_bytes(p, "big") + int.from_bytes(q, "big")).to_bytes(w, "big")
    return bytes(out)


# ---- text clarity: levels + unsharp mask ----------------------------------------
# After shading, ink only reaches ~80-100 (the CIS sees some light through and
# around it) and edges are soft. The vendor driver applies gamma/contrast tables
# and optional edge emphasis; this is the equivalent done in software.

def levels_lut(img, black=None, white=None, gamma=1.0):
    """LUT stretching [black, white] to [0, 255].
    black=None: auto from the darkest 0.3% of pixels (capped so blank pages are
    left alone). white=None: auto from the paper level (median - 2*(median -
    lower quartile) of pixels >= 150), kept within 200..250."""
    hist = [0] * 256
    for v, c in __import__("collections").Counter(img[::7]).items():
        hist[v] = c
    if black is None:
        n, acc, black = sum(hist) * 0.003, 0, 0
        for v in range(256):
            acc += hist[v]
            if acc >= n:
                black = v
                break
        black = min(max(black - 10, 0), 110)
    if white is None:
        # paper = pixels >= 150; put the white point two lower-quartile spreads
        # under the paper median so the paper texture becomes clean white
        paper = hist[150:]
        tot = sum(paper)
        med = q1 = 255
        if tot:
            acc = 0
            for i, c in enumerate(paper):
                acc += c
                if q1 == 255 and acc >= tot * 0.25:
                    q1 = 150 + i
                if acc >= tot * 0.5:
                    med = 150 + i
                    break
        white = min(250, max(200, med - 2 * (med - q1)))
    span = max(1, white - black)
    return bytes(0 if v <= black else 255 if v >= white else
                 int(255 * ((v - black) / span) ** gamma + 0.5) for v in range(256))


def sharpen(img, w, h, amount=0.75, radius=1):
    """Unsharp mask with a (2r+1)^2 box blur: out = p + amount*(p - mean).
    Rows are held as big ints with one 16-bit lane per pixel, so the box sums
    are a handful of big-int adds per row; one LUT pass maps lanes to bytes."""
    import array, sys
    if amount <= 0 or w < 3 or h < 3:
        return img
    r = radius
    n = (2 * r + 1) ** 2
    d = max(1, round(n / amount))
    c = n + d                                   # out = (c*p - S) / d
    bias = n * 255
    lut = [0] * (c * 255 + bias + 1)
    for v in range(len(lut)):
        q = (v - bias) // d
        lut[v] = 0 if q < 0 else 255 if q > 255 else q
    lanes = bytearray(2 * w)
    mask = (1 << (16 * w)) - 1
    biasrow = int.from_bytes(bytes([bias >> 8, bias & 255]) * w, "big")
    rows, hs = [], []
    for y in range(h):
        lanes[1::2] = img[y * w:(y + 1) * w]
        R = int.from_bytes(lanes, "big")
        H = R
        for k in range(1, r + 1):
            H += ((R << (16 * k)) & mask) + (R >> (16 * k))
        rows.append(R)
        hs.append(H)
    out = bytearray(w * h)
    swap = sys.byteorder == "little"
    S = sum(hs[min(max(k, 0), h - 1)] for k in range(-r - 1, r))   # window ending at row r-1
    for y in range(h):
        S += hs[min(y + r, h - 1)] - hs[min(max(y - r - 1, 0), h - 1)]
        v = c * rows[y] + biasrow - S
        a = array.array("H", v.to_bytes(2 * w, "big"))
        if swap:
            a.byteswap()
        out[y * w:(y + 1) * w] = bytes(map(lut.__getitem__, a))
    return bytes(out)


def enhance(chans, w, h, a):
    """Apply levels (one curve for all planes, from green/gray) and sharpening."""
    g = chans[1] if len(chans) == 3 else chans[0]
    lut = levels_lut(g, a.black_point, a.white_point, a.gamma)
    radius = max(1, a.dpi // 300)
    amount = a.sharpen if a.sharpen is not None else (0.75 if a.dpi == 300 else 0.4)
    chans = [c.translate(lut) for c in chans]
    if len(chans) == 3 and a.chroma_denoise:
        # Per-channel sensor noise shows as pink/cyan specks on white paper once
        # highlights are no longer clipped: smooth R-G and B-G in near-neutral
        # areas first. (Sharpening only brightness instead was tried; adding G's
        # halftone texture to saturated channels shifts printed colours.)
        r, g, b = chans
        chans = [chroma_denoise(r, g, w, h, a.chroma_denoise), g,
                 chroma_denoise(b, g, w, h, a.chroma_denoise)]
    return [sharpen(c, w, h, amount, radius) for c in chans]


def chroma_denoise(c, g, w, h, radius=2, tol=12):
    """c' = g + boxblur(c - g): smooth the colour difference to green over a
    (2r+1)^2 box while keeping full-resolution brightness (g). Removes the
    per-channel sensor noise that shows as pink/cyan specks on white paper.
    16-bit lanes: diff + 255 in 0..510, box sum <= 25*510 (r=2)."""
    import array, sys
    n = (2 * radius + 1) ** 2
    lo = n * 255
    top = n * 255 + n * 510
    lut = [0] * (top + 1)
    for v in range(top + 1):
        q = (v - lo + n // 2) // n
        lut[v] = 0 if q < 0 else 255 if q > 255 else q
    lanes = bytearray(2 * w)
    mask = (1 << (16 * w)) - 1
    off = int.from_bytes(b"\x00\xff" * w, "big")          # +255 per lane
    swap = sys.byteorder == "little"

    def tolane(row):
        lanes[1::2] = row
        return int.from_bytes(lanes, "big")

    gl, hs = [], []
    for y in range(h):
        sl = slice(y * w, (y + 1) * w)
        G = tolane(g[sl])
        D = tolane(c[sl]) + off - G
        H = D
        for k in range(1, radius + 1):
            H += ((D << (16 * k)) & mask) + (D >> (16 * k))
        gl.append(G)
        hs.append(H)
    # only near-neutral areas (|mean(c - g)| <= tol) are smoothed, so printed
    # colour (halftone dots of different inks) is left exactly as scanned
    gate = [0] * (n * 510 + 1)
    for v in range(len(gate)):
        if abs(v - lo) <= n * tol:
            gate[v] = 255
    out = bytearray(w * h)
    S = sum(hs[min(max(k, 0), h - 1)] for k in range(-radius - 1, radius))
    for y in range(h):
        S += hs[min(y + radius, h - 1)] - hs[min(max(y - radius - 1, 0), h - 1)]
        v = n * gl[y] + S               # n*g + sum(c - g + 255); edge columns see fewer terms
        arr = array.array("H", v.to_bytes(2 * w, "big"))
        sarr = array.array("H", S.to_bytes(2 * w, "big"))
        if swap:
            arr.byteswap()
            sarr.byteswap()
        sm = int.from_bytes(bytes(map(lut.__getitem__, arr)), "big")
        gm = int.from_bytes(bytes(map(gate.__getitem__, sarr)), "big")
        orig = c[y * w:(y + 1) * w]
        mixed = (sm & gm) | (int.from_bytes(orig, "big") & ~gm)
        row = bytearray(mixed.to_bytes(w, "big"))
        row[:radius] = c[y * w:y * w + radius]            # window runs off the edge:
        row[w - radius:] = c[(y + 1) * w - radius:(y + 1) * w]   # keep the original there
        out[y * w:(y + 1) * w] = row
    return bytes(out)


def to_bilevel(img, w, h, threshold=170, despeckle_on=True):
    """8-bit gray -> packed 1-bit rows (MSB first, 1 = white, rows padded to a
    byte), the layout PNG and PDF both use. Each of the 8 bit positions is a
    translate to its bit weight; the disjoint bits are summed as one big int."""
    pad = -w % 8
    if pad:
        white = b"\xff" * pad
        img = b"".join(img[y * w:(y + 1) * w] + white for y in range(h))
    acc = 0
    for k in range(8):
        t = bytes((0x80 >> k) if v >= threshold else 0 for v in range(256))
        acc += int.from_bytes(img[k::8].translate(t), "big")
    packed = acc.to_bytes(len(img) // 8, "big")
    return despeckle(packed, (w + pad) // 8, h) if despeckle_on else packed


def despeckle(packed, stride, h):
    """Turn isolated black pixels (no black among the 8 neighbours) white.
    Works on whole rows as big ints (black = 1 after inverting)."""
    nbits = stride * 8
    full = (1 << nbits) - 1
    rows = [full ^ int.from_bytes(packed[y * stride:(y + 1) * stride], "big") for y in range(h)]
    out = bytearray(len(packed))
    for y in range(h):
        r = rows[y]
        if r:
            up = rows[y - 1] if y else 0
            dn = rows[y + 1] if y + 1 < h else 0
            v = up | dn
            nb = ((r << 1) | (r >> 1) | v | (v << 1) | (v >> 1)) & full
            r &= nb                                   # keep pixels with a neighbour
        out[y * stride:(y + 1) * stride] = (full ^ r).to_bytes(stride, "big")
    return bytes(out)


# ---- page classification: blank / colour ------------------------------------------

def ink_coverage(g, w, h, dpi):
    """Percent of interior pixels (0.25" in from the edges) darker than 128.
    Run on the enhanced page, where paper is white and ink is dark."""
    m = dpi // 4
    if w <= 2 * m or h <= 2 * m:
        return 100.0
    mask = bytes(1 if v < 128 else 0 for v in range(256))
    n = k = 0
    for y in range(m, h - m, 2):
        row = g[y * w + m:(y + 1) * w - m:2]
        k += row.translate(mask).count(1)
        n += len(row)
    return 100.0 * k / n


def dark_coverage(g, w, h, dpi, frac=0.35):
    """Blank-page metric on the shaded (not contrast-stretched) page: percent of
    interior pixels darker than frac * paper level. Real ink is ~5-30 against
    paper ~230; show-through from the other side never gets that dark."""
    m = dpi // 4
    if w <= 2 * m or h <= 2 * m:
        return 100.0
    sample = sorted(g[m * w + m:(h - m) * w:211])
    paper = sample[len(sample) * 3 // 4] if sample else 255      # paper dominates a blank page
    cut = int(paper * frac)
    mask = bytes(1 if v < cut else 0 for v in range(256))
    n = k = 0
    for y in range(m, h - m, 2):
        row = g[y * w + m:(y + 1) * w - m:2]
        k += row.translate(mask).count(1)
        n += len(row)
    return 100.0 * k / n


def to_luma(chans, w, h):
    """RGB planes -> gray (Rec.601 weights 77/150/29 /256) via 16-bit lanes."""
    import array, sys
    r, g, b = chans
    lut = bytes(min(255, v >> 8) for v in range(65536))
    lanes = bytearray(2 * w)
    swap = sys.byteorder == "little"
    out = bytearray(w * h)

    def tolane(row):
        lanes[1::2] = row
        return int.from_bytes(lanes, "big")
    for y in range(h):
        sl = slice(y * w, (y + 1) * w)
        v = 77 * tolane(r[sl]) + 150 * tolane(g[sl]) + 29 * tolane(b[sl])
        arr = array.array("H", v.to_bytes(2 * w, "big"))
        if swap:
            arr.byteswap()
        out[sl] = bytes(map(lut.__getitem__, arr))
    return bytes(out)


def colour_coverage(chans, w, h, dpi, block=6, thr=36):
    """Percent of interior blocks (block x block px) whose mean colour has
    max-min channel spread > thr. Averaging over a block cancels the red/blue
    fringes at black text edges (they alternate sides), real colour survives."""
    import array, sys
    m = dpi // 4
    x0, x1 = m, w - m - (w - 2 * m) % block
    if x1 - x0 < block or h - 2 * m < block:
        return 0.0
    nb = (x1 - x0) // block
    swap = sys.byteorder == "little"
    lanes = bytearray(2 * (x1 - x0))
    area = block * block
    hits = total = 0
    for by in range(m, h - m - block + 1, block):
        means = []
        for c in chans:
            acc = 0
            for y in range(by, by + block):
                lanes[1::2] = c[y * w + x0:y * w + x1]
                acc += int.from_bytes(lanes, "big")      # 16-bit lanes: <= 6*255
            a = array.array("H", acc.to_bytes(len(lanes), "big"))
            if swap:
                a.byteswap()
            means.append([sum(a[i:i + block]) for i in range(0, len(a), block)])
        for rs, gs, bs in zip(*means):
            hi = rs if rs > gs else gs
            hi = bs if bs > hi else hi
            lo = rs if rs < gs else gs
            lo = bs if bs < lo else lo
            hits += hi - lo > thr * area
        total += nb
    return 100.0 * hits / max(1, total)


# ---- factory light-curve correction (vendor AdjustLightFix) ---------------------
# Scanner memory 0x10080000 (0x80000 bytes) holds per-pixel factory curves:
# header <u32 timestamp, u32 0, u32 count>, then records of
# <u16 hdrlen, u16 side, u16 planes, u16 bits, u32 divisor, u32 width,
#  u32 plane_bytes, u32 data_bytes, u16 dpi, u16 per_plane, u32 flags,
#  u8 dropout, u8 emphasis> + data (little-endian). The vendor replaces the
# white reference with black + max(0, white - black) * curve[x] / divisor.
LIGHTCURVE_ADDR, LIGHTCURVE_SIZE = 0x10080000, 0x80000


def parse_light_curves(buf):
    """-> {(side, planes, dpi): (divisor, [plane][x])} for the plain records
    (no colour dropout / emphasis, flags bit0 set). {} if no data."""
    if len(buf) < 12 or buf[:4] == b"\xff\xff\xff\xff":
        return {}
    _, _, count = struct.unpack_from("<III", buf, 0)
    off, out = 12, {}
    for _ in range(count):
        if off + 32 > len(buf):
            break
        hl, side, planes, bits, div, w, pbytes, size, dpi, per_plane, flags = \
            struct.unpack_from("<HHHHIIIIHHI", buf, off)
        if hl == 0:
            break
        dropout = buf[off + 32] if hl > 32 else 0
        emphasis = buf[off + 33] if hl > 33 else 0
        data = buf[off + hl:off + hl + size]
        off += hl + size
        if bits != 16 or dropout or emphasis or not flags & 1 or not div:
            continue
        vals = struct.unpack("<%dH" % (len(data) // 2), data)
        stride = pbytes // 2
        curve = [list(vals[p * stride:p * stride + w]) for p in range(planes)] if per_plane \
            else [list(vals[:w])] * planes
        out[(side, planes, dpi)] = (div, curve)
    return out


def load_light_curves(r, serial, log):
    """Factory curves, cached per scanner; re-read when the timestamp changes."""
    path = os.path.join(CAL_CACHE_DIR, "%s-lightcurve.bin" % serial)
    stamp = r.read_buffer(LIGHTCURVE_ADDR, 0x200)[:4]
    try:
        with open(path, "rb") as f:
            buf = f.read()
        if buf[:4] != stamp:
            buf = None
    except OSError:
        buf = None
    if buf is None:
        log("reading factory light-curve data...")
        buf = b"".join(r.read_buffer(LIGHTCURVE_ADDR + o, 0x10000)
                       for o in range(0, LIGHTCURVE_SIZE, 0x10000))
        try:
            os.makedirs(CAL_CACHE_DIR, exist_ok=True)
            with open(path + ".tmp", "wb") as f:
                f.write(buf)
            os.replace(path + ".tmp", path)
        except OSError:
            pass
    return parse_light_curves(buf)


def apply_light_curve(white, black, div, curve):
    """Vendor CLightCurveAdjustData::AdjustData on one plane."""
    out = list(white)
    for x in range(min(len(white), len(curve))):
        d = white[x] - black[x]
        if d < 0:
            d = 0
        out[x] = min(0xFFFF, (d * curve[x] + (div >> 1)) // div + black[x])
    return out


CAL_CACHE_DIR = os.path.join(os.environ.get("XDG_CACHE_HOME", os.path.expanduser("~/.cache")), "canon_r10")


def scanner_serial(r):
    import re
    d = r.read(6, 0x80)
    m = re.findall(rb"[A-Z0-9]{6,}", d)
    return m[-1].decode() if m else "unknown"


def load_calibration(key, max_age):
    import json
    path = os.path.join(CAL_CACHE_DIR, key + ".json")
    try:
        with open(path) as f:
            d = json.load(f)
    except (OSError, ValueError):
        return None
    if time.time() - d.get("time", 0) > max_age:
        return None
    return d


def save_calibration(key, d):
    import json
    os.makedirs(CAL_CACHE_DIR, exist_ok=True)
    d = dict(d, time=time.time())
    tmp = os.path.join(CAL_CACHE_DIR, key + ".json.tmp")
    with open(tmp, "w") as f:
        json.dump(d, f)
    os.replace(tmp, os.path.join(CAL_CACHE_DIR, key + ".json"))


def cmd_scan(r, a):
    log = lambda m: print(m, file=sys.stderr)
    r.t.execute(bytes(6))                                # TEST UNIT READY
    caps = r.inquiry_ex()
    log("caps: %s" % {k: v for k, v in caps.items() if k != "raw"})
    if a.dpi not in (300, 600):
        raise ScannerError("the R10 scans at 300 or 600 dpi")
    if a.button:
        log("load a sheet and press the scanner button (Ctrl-C to cancel)...")
        while True:
            r.wait_button()
            if r.document_ready():
                break
            log("no paper loaded - load a sheet and press the button again")
    if a.wait_paper:
        log("waiting for paper - feed a sheet (scanner button or Ctrl-C cancels)...")
        while True:
            got = wait_for_sheet(r)
            if got != "paper":
                log("cancelled - nothing scanned")
                return
            if r.document_ready():                    # still there: start
                break
            log("paper not detected any more - still waiting...")
    ready = r.document_ready()
    log("document ready status: %02x" % ready)
    if not ready and not a.no_paper_check:
        raise ScannerError("no paper in the feeder")
    color = a.mode in ("color", "auto")
    comp = 5 if color else 2
    if a.color_shift is None:
        a.color_shift = [1 / 3, -1 / 3] if a.dpi == 300 else [0.25, -0.25]
    # DEFINE SCAN MODE 0x32 byte 6: 0 = window 0 only (side A), 1 = window 1 only
    # (side B), 2 = duplex (both windows, pixel-interleaved A/B)
    if a.duplex:
        side, ids = 2, [0, 1]
    elif a.side_b:
        side, ids = 1, [1]
    else:
        side, ids = 0, [0]
    w = caps["width_1200"] * a.dpi // 1200

    luts = None
    if not a.no_calibrate:
        cal_sides = 1 if side == 0 else 2
        cal = Calibrator(r, caps["width_1200"], a.dpi, color, cal_sides,
                         0 if cal_sides == 1 else 2, log if a.verbose else (lambda m: None))
        key = "%s-%s-%d-%d" % (scanner_serial(r), "color" if color else "gray", a.dpi, cal_sides)
        if not a.no_light_curve:
            try:
                cal.curves = load_light_curves(r, scanner_serial(r), log)
            except ScannerError as e:
                log("factory light curve unavailable (%s)" % e)
        cached = None if a.recalibrate else load_calibration(key, a.cal_max_age)
        if cached:
            log("using cached calibration %s (%.0fs old)" % (key, time.time() - cached["time"]))
            luts = cal.restore(cached)
        else:
            log("calibrating (%s, %d dpi, %d side(s))..." % (a.mode, a.dpi, cal_sides))
            t0 = time.time()
            luts = cal.run()
            save_calibration(key, cal.to_dict())
            log("calibration done in %.1fs" % (time.time() - t0))
        if side == 1:
            luts = [luts[1]]
        elif side == 0:
            luts = [luts[0]]

    # Window length: the R10 stops by itself ~20 lines after the trailing edge,
    # so ask for the maximum and let the paper decide (--length overrides).
    # In auto mode start 0.39" early (vendor auto-size overscan: uly -0x1D8,
    # length +0x3B0) so the leading edge and its corners are always captured.
    if a.length:
        uly, length = 0, int(a.length * 1200)
    else:
        uly, length = -0x1D8, caps["max_length"] * 1200 // caps["base_yres"] + 0x3B0
    def start_scan():
        for wid in (0, 1):
            r.set_window(wid, a.dpi, a.dpi, 0, uly & 0xFFFFFFFF, caps["width_1200"], length, comp)
        r.define_scan_mode(0x30, b"")                    # double-feed detection off
        r.define_scan_mode(0x32, bytes([side, 1]))       # side mode, buffering
        r.define_scan_mode(0x36, b"")                    # no colour dropout
        r.scan(ids)

    def start_scan_retry(attempts=3):
        """SCAN can fail with 'no paper' (3/3A or 5/3A) when the sheet sensor
        flickers or the sheet slips back after being detected. Wait for the
        sheet to settle again and retry; False if it never takes."""
        for n in range(1, attempts + 1):
            try:
                start_scan()
                return True
            except DeviceError as e:
                if e.asc != 0x3A or n == attempts:
                    if e.asc == 0x3A:
                        log("no paper after %d attempts - finishing" % attempts)
                        return False
                    raise
                log("no paper at scan start (attempt %d of %d) - waiting for the sheet..."
                    % (n, attempts))
                if wait_for_sheet(r, timeout=30) != "paper":
                    log("no sheet - finishing")
                    return False
        return False

    log("side mode %d, window ids %s" % (side, ids))
    if not start_scan_retry():
        return

    jpeg_q = a.jpeg_quality if a.mode in ("color", "auto") else 0   # only colour pages use JPEG
    sink = (PdfSink(a.out, a.dpi, jpeg_q, log) if a.out.lower().endswith(".pdf")
            else PngSink(a.out))
    page = 0
    try:
        while True:
            data, (key, asc, ascq, info, raw) = r.read_page(log=log if a.verbose else None)
            if data:
                if a.keep_raw:
                    with open("%s.page%03d.raw" % (a.out.rstrip("/"), page), "wb") as f:
                        f.write(data)
                try:
                    pinfo = r.page_info()
                except ScannerError:
                    pinfo = {"paper_length": 0}
                if a.verbose:
                    log("  page info %s" % pinfo)
                too_long = pinfo["paper_length"] < 0     # no trailing edge seen
                if too_long:
                    log("warning: sheet %d is longer than the scanner's maximum length "
                        "(%.1f in); only the first part was scanned and the rest is "
                        "probably still in the scanner. For long sheets use long document "
                        "mode: canon_r10.py max-length 1000 (or 3000)"
                        % (page, caps["max_length"] / caps["base_yres"]))
                plen = max(0, pinfo["paper_length"]) * a.dpi // 1200
                vbin = line_multiplier(len(data) // (w * len(ids) * (3 if color else 1)),
                                       pinfo["paper_length"], a.dpi)
                if vbin > 1:
                    log("scanner returned %dx lines per paper line (long document mode, "
                        "gray); merging every %d lines" % (vbin, vbin))
                sides = process_sides(data, w, ids, 3 if color else 1, luts, a, log, plen, vbin)
                order = sorted(sides, key=lambda t: a.order.index(t[0])) if len(sides) > 1 else sides
                for label, iw, ih, ch, img in order:
                    sink.add(page, label, iw, ih, ch, img, log)
                page += 1
                if too_long:
                    # the R10 stops the motor and latches a jam (3/80 00); report it
                    r.read(5, 1, check=False)
                    if r.t.status:
                        key, asc, ascq = r.t.sense()[:3]
                    msg, adv = describe_sense(key, asc, ascq)
                    log("stopping: %s (sense %x/%02x %02x) - %s" % (msg, key, asc, ascq, adv)
                        if msg else "stopping after the over-long sheet")
                    break
            if key == 3 and asc == 0x3A:
                break                                    # feeder empty
            if key not in (0, 1):
                msg, adv = describe_sense(key, asc, ascq)
                log("stopping: %s (sense %x/%02x %02x) - %s" % (msg, key, asc, ascq, adv))
                break
            if not data or a.single:
                break
            if not next_page(r, a.feed_timeout, log, a.verbose, a.button):
                break
            if not start_scan_retry():                   # the R10 needs a SCAN per sheet
                break
    finally:
        sink.close(log)
    log("%d sheet(s) scanned" % page)


def wait_for_sheet(r, timeout=-1, settle=0.8, poll=0.08):
    """Wait until a sheet is loaded and stays loaded for `settle` s (the paper
    sensor flickers while a sheet is being inserted). The scanner button ends
    the wait. -> "paper", "button", "timeout" or "interrupt"."""
    t0 = time.time()
    since = None                                  # time paper was first seen (current run)
    n = 0
    try:
        while timeout < 0 or time.time() - t0 < timeout:
            if r.button_down():
                while r.button_down():
                    time.sleep(poll)
                return "button"
            n += 1
            if n % 3 == 0:                            # paper check every ~0.25 s
                if r.document_ready():
                    since = since or time.time()
                    if time.time() - since >= settle:
                        return "paper"
                else:
                    since = None
            time.sleep(poll)
    except KeyboardInterrupt:
        return "interrupt"
    return "timeout"


def next_page(r, feed_timeout, log, verbose, button=False):
    """Between sheets the vendor driver polls READ dtc A1 until it is non-zero
    (sheet finished/ejected). Then wait for the next sheet to be fed; returns
    False if none arrives within feed_timeout seconds."""
    t0 = time.time()
    while time.time() - t0 < 15:
        v = r.read(8, 1, check=False)
        if r.t.status:
            r.t.sense()
            break
        if v[0]:
            break
        time.sleep(0.2)
    if button:
        try:
            while True:
                log("load the next sheet and press the scanner button "
                    "(press with no paper, or Ctrl-C, to finish)...")
                r.wait_button()
                if r.document_ready():
                    time.sleep(0.3)
                    return True
                log("no paper loaded - finishing")
                return False
        except KeyboardInterrupt:
            log("finishing")
            return False
    if feed_timeout == 0:
        return bool(r.document_ready())
    log("feed the next sheet, or press the scanner button to finish%s..."
        % ("" if feed_timeout < 0 else " (waiting %ds)" % feed_timeout))
    t0 = time.time()
    while True:
        left = -1 if feed_timeout < 0 else max(0.0, feed_timeout - (time.time() - t0))
        got = wait_for_sheet(r, left)
        if got == "paper":
            if r.document_ready():
                return True
            log("paper not detected any more - still waiting...")
            continue
        log({"button": "button pressed - finishing", "interrupt": "finishing",
             "timeout": "no sheet fed - finishing"}[got])
        return False


def write_png(path, width, height, channels, data):
    import zlib
    stride = (width + 7) // 8 if channels == 0 else width * channels     # 0 = 1-bit gray
    raw = b"".join(b"\0" + data[y * stride:(y + 1) * stride] for y in range(height))
    chunk = lambda t, b: struct.pack(">I", len(b)) + t + b + struct.pack(">I", zlib.crc32(t + b))
    ctype = {0: 0, 1: 0, 3: 2}[channels]
    depth = 1 if channels == 0 else 8
    with open(path, "wb") as f:
        f.write(b"\x89PNG\r\n\x1a\n"
                + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, depth, ctype, 0, 0, 0))
                + chunk(b"IDAT", zlib.compress(raw, 6)) + chunk(b"IEND", b""))


def normalize(data, width, height, black_pct=0.02, white_pct=0.98):
    """Poor-man's shading correction until the vendor calibration is ported:
    stretch every column between its own dark and bright percentile."""
    lut_rows = []
    out = bytearray(len(data))
    step = max(1, height // 400)
    for x in range(width):
        col = sorted(data[x:len(data):width * step])
        lo = col[int(len(col) * black_pct)]
        hi = max(col[int(len(col) * white_pct) - 1], lo + 1)
        lut_rows.append(bytes(min(255, max(0, (v - lo) * 255 // (hi - lo))) for v in range(256)))
    for y in range(height):
        o = y * width
        for x in range(width):
            out[o + x] = lut_rows[x][data[o + x]]
    return bytes(out)


def flip_vertical(data, width, height, channels=1):
    stride = width * channels
    return b"".join(data[y * stride:(y + 1) * stride] for y in range(height - 1, -1, -1))


def line_multiplier(lines, paper_len_1200, dpi):
    """In long document mode gray scans come back with every paper line
    repeated ~3x (the motor runs at colour speed; measured 3.02-3.05x on nine
    A4 sheets). Compare lines received with what the scanner's own
    paper-length measurement predicts (+0.39" lead-in overscan and ~20 trailing
    lines); return the whole-number factor, or 1 if the data is normal."""
    if paper_len_1200 <= 0:
        return 1
    expected = (paper_len_1200 + 0x1D8) * dpi / 1200.0 + 20
    r = lines / expected
    k = int(round(r))
    return k if 2 <= k <= 4 and abs(r - k) < 0.3 else 1


def vertical_bin(img, w, h, k):
    """Average every k rows into one (16-bit lanes, one LUT pass)."""
    import array, sys
    lut = bytes(min(255, (v + k // 2) // k) for v in range(255 * k + 1))
    lanes = bytearray(2 * w)
    swap = sys.byteorder == "little"
    nh = h // k
    out = bytearray(w * nh)
    for y in range(nh):
        acc = 0
        for j in range(k):
            lanes[1::2] = img[(y * k + j) * w:(y * k + j + 1) * w]
            acc += int.from_bytes(lanes, "big")
        arr = array.array("H", acc.to_bytes(2 * w, "big"))
        if swap:
            arr.byteswap()
        out[y * w:(y + 1) * w] = bytes(map(lut.__getitem__, arr))
    return bytes(out), nh


def process_sides(data, w, ids, planes, luts, a, log, paper_len=0, vbin=1):
    """Split sides (duplex: pixel-interleaved A/B) and colour planes (line-planar),
    apply shading, colour registration, orientation, deskew and crop.
    Window 0 (side A) arrives bottom-up; window 1 (side B) arrives rotated 180.
    Returns [(label, width, height, channels, interleaved bytes)]."""
    n = len(ids)
    line = w * n * planes
    if len(data) % line:
        data = data[:len(data) - len(data) % line]
    h = len(data) // line
    result = []
    for i, wid in enumerate(ids):
        chans = []
        for p in range(planes):
            img = b"".join(data[y * line + p * w * n:y * line + (p + 1) * w * n][i::n]
                           for y in range(h))
            if luts is not None:
                img = apply_luts(img, w, luts[i][p])
            elif not a.no_normalize:
                img = normalize(img, w, h)
            ph = h
            if vbin > 1:
                img, ph = vertical_bin(img, w, h, vbin)
            if planes == 3 and p != 1:
                # CIS lights R, G, B in sequence: R and B are sampled ~1/3 line
                # either side of G; resample them onto G's position.
                img = shift_rows(img, w, ph, a.color_shift[0] if p == 0 else a.color_shift[1])
            if not a.no_flip:
                img = img[::-1] if wid == 1 else flip_vertical(img, w, ph)
            chans.append(img)
        iw, ih = w, ph
        if not a.no_align:
            chans, iw, ih = align_page(chans, w, ph, log, "A" if wid == 0 else "B", paper_len, a.dpi)
        label = "A" if wid == 0 else "B"
        if a.skip_blank:
            dark = dark_coverage(chans[1] if planes == 3 else chans[0], iw, ih, a.dpi)
            if dark < a.blank_threshold:
                log("side %s: blank (ink %.4f%% < %.4f%%) - skipped" % (label, dark, a.blank_threshold))
                continue
            log("side %s: not blank (ink %.3f%%)" % (label, dark))
        if not a.no_enhance:
            chans = enhance(chans, iw, ih, a)
        if a.mode == "auto":
            cov = colour_coverage(chans, iw, ih, a.dpi)
            if cov < a.colour_threshold:
                log("side %s: no colour (%.3f%% < %.2f%%) - saved as gray" % (label, cov, a.colour_threshold))
                result.append((label, iw, ih, 1, to_luma(chans, iw, ih)))
                continue
            log("side %s: colour (%.3f%%)" % (label, cov))
        if a.mode == "bw":
            result.append(("A" if wid == 0 else "B", iw, ih, 0, to_bilevel(chans[0], iw, ih, a.threshold, not a.no_despeckle)))
            continue
        if planes == 1:
            out = chans[0]
        else:
            o = bytearray(iw * ih * 3)
            for c in range(3):
                o[c::3] = chans[c]
            out = bytes(o)
        result.append(("A" if wid == 0 else "B", iw, ih, planes, out))
    return result


# ---- paper alignment: deskew + crop from the paper-edge shadows ----------------
# After shading both the backing and the paper are ~255; the paper edges show up
# only as thin dark shadow lines (and only on the edges facing away from the
# light). Text can sit close to the edge, so an edge is accepted only if a
# single straight line explains the dark points along most of its length.
EDGE_THR = 200
_MASK = bytes(1 if v < EDGE_THR else 0 for v in range(256))


def _first_dark(seq):
    i = seq.translate(_MASK).find(1)
    return i if i >= 0 else None


def edge_samples(g, w, h, margin=130, step=8, vmargin=260):
    """Outermost dark pixel per sampled row/column in each margin band.
    left/right: (y, x); top/bottom: (x, y)."""
    pts = {"left": [], "right": [], "top": [], "bottom": []}
    for y in range(0, h, step):
        row = g[y * w:(y + 1) * w]
        i = _first_dark(row[:margin])
        if i is not None:
            pts["left"].append((y, i))
        i = _first_dark(row[w - margin:][::-1])
        if i is not None:
            pts["right"].append((y, w - 1 - i))
    mh = min(vmargin, h)
    for x in range(0, w, step):
        col = g[x::w]
        i = _first_dark(col[:mh])
        if i is not None:
            pts["top"].append((x, i))
        i = _first_dark(col[h - mh:][::-1])
        if i is not None:
            pts["bottom"].append((x, h - 1 - i))
    return pts


def ransac_line(pts, n_total, min_frac, tol=2.5, max_slope=0.08, iters=300, min_sep=None):
    """Best straight line v = a + b*u through pts. Returns (a, b, inliers) if the
    inliers cover at least min_frac of the n_total samples, else None."""
    import random
    if len(pts) < max(8, n_total * min_frac):
        return None
    rnd = random.Random(1)
    best = []
    for _ in range(iters):
        (u1, v1), (u2, v2) = rnd.sample(pts, 2)
        if abs(u2 - u1) < (min_sep or n_total):   # want well separated pairs
            continue
        b = (v2 - v1) / (u2 - u1)
        if abs(b) > max_slope:
            continue
        a = v1 - b * u1
        inl = [(u, v) for u, v in pts if abs(v - a - b * u) <= tol]
        if len(inl) > len(best):
            best = inl
    if len(best) < max(8, n_total * min_frac):
        return None
    n = len(best)
    su = sum(u for u, _ in best); sv = sum(v for _, v in best)
    suu = sum(u * u for u, _ in best); suv = sum(u * v for u, v in best)
    den = n * suu - su * su
    b = (n * suv - su * sv) / den if den else 0.0
    return sv / n - b * su / n, b, best


def find_paper_lines(g, w, h, dpi=300):
    """All distances scale with resolution: side bands 0.45", top/bottom
    bands 1.1", line tolerance 2.5 px at 300 dpi."""
    k = dpi / 300.0
    step = int(8 * k)
    pts = edge_samples(g, w, h, margin=int(130 * k), step=step, vmargin=int(330 * k))
    nv, nh = h // step, w // step
    tol = 2.5 * k
    return {
        "left": ransac_line(pts["left"], nv, 0.5, tol, min_sep=h // 4),
        "right": ransac_line(pts["right"], nv, 0.5, tol, min_sep=h // 4),
        "top": ransac_line(pts["top"], nh, 0.35, tol, min_sep=w // 4),
        "bottom": ransac_line(pts["bottom"], nh, 0.35, tol, min_sep=w // 4),
    }


def shear_rows(img, w, h, s, fill=255):
    """Shift row y horizontally by -s*(y - h/2) (nearest pixel)."""
    out = bytearray(len(img))
    pad = bytes([fill]) * w
    for y in range(h):
        d = int(round(-s * (y - h / 2)))
        row = img[y * w:(y + 1) * w]
        if d > 0:
            row = pad[:d] + row[:w - d]
        elif d < 0:
            row = row[-d:] + pad[:-d]
        out[y * w:(y + 1) * w] = row
    return bytes(out)


def shear_cols(img, w, h, s, fill=255):
    """Shift column x vertically by s*(x - w/2) (nearest pixel)."""
    out = bytearray(img)
    pad = bytes([fill]) * h
    for x in range(w):
        d = int(round(s * (x - w / 2)))
        if not d:
            continue
        col = img[x::w]
        if d > 0:
            col = pad[:d] + col[:h - d]
        else:
            col = col[-d:] + pad[:-d]
        out[x::w] = col
    return bytes(out)


def _inset(g, w, h, pos, axis, direction, span, limit=40):
    """Walk from an edge line into the paper until the shadow gradient is gone:
    the band mean reaches white, or stops changing (dark or coloured paper
    never reaches white). axis 'x': pos is a column, mean over rows in span."""
    lo, hi = span
    idx = range(lo, hi, 7)
    prev = None
    for k in range(1, limit):
        p = pos + direction * k
        if axis == "x":
            if not 0 <= p < w:
                return k
            m = sum(g[y * w + p] for y in idx) / max(1, len(idx))
        else:
            if not 0 <= p < h:
                return k
            m = sum(g[p * w + x] for x in idx) / max(1, len(idx))
        if m >= 250:
            return k + 1
        if prev is not None and k >= 3 and abs(m - prev) < 1.5:
            return k
        prev = m
    return limit

def estimate_skew(g, w, h, max_deg=5.0, dpi=300, detail=False):
    """Content-based skew (projection profile): the angle at which the dark
    pixels' row histogram is sharpest. Returns s = dx/dy of vertical lines, or
    None when the page has too little content."""
    sx = sy = max(3, 3 * dpi // 300)
    mg = dpi // 3
    # "ink" is dark on light pages and light on dark pages (white-on-black print)
    body = g[mg * w:(h - mg) * w:97]
    dark = sum(1 for v in body if v < 128) > len(body) // 2
    mask = bytes(1 if (v > 160 if dark else v < 128) else 0 for v in range(256))
    pts = []
    for y in range(mg, h - mg, sy):
        row = g[y * w + mg:(y + 1) * w - mg:sx].translate(mask)
        i = row.find(1)
        while i >= 0:
            pts.append((i * sx + mg, y))
            i = row.find(1, i + 1)
    if len(pts) < 2000:
        return None
    if len(pts) > 40000:                         # keep it quick on dense pages
        pts = pts[::len(pts) // 40000 + 1]

    def score(deg, vertical):
        # horizontal text: bins of y + x*t; sideways text: bins of x - y*t.
        # Both give s = t (dx/dy of the page's vertical lines).
        t = math.tan(math.radians(deg))
        hist = {}
        if vertical:
            for x, y in pts:
                k = int(x - y * t) // sx
                hist[k] = hist.get(k, 0) + 1
        else:
            for x, y in pts:
                k = int(y + x * t) // sy
                hist[k] = hist.get(k, 0) + 1
        return sum(c * c for c in hist.values())

    coarse = [d / 4 for d in range(int(-max_deg * 4), int(max_deg * 4) + 1)]
    picks = []
    for vertical in (False, True):
        sc = [(score(d, vertical), d) for d in coarse]
        top_score, best = max(sc)
        gain = top_score / (sum(v for v, _ in sc) / len(sc))   # how sharp the best angle is
        picks.append((gain, best, vertical))
    gain, best, vertical = max(picks)
    best = max((score(best + d / 40, vertical), best + d / 40) for d in range(-10, 11))[1]
    if not detail:
        return math.tan(math.radians(best))
    # the other orientation too (horizontal text: vertical rules/column edges)
    ogain, obest, overt = min(picks)
    obest = max((score(obest + d / 40, overt), obest + d / 40) for d in range(-10, 11))[1]
    return {"s": math.tan(math.radians(best)), "gain": gain, "vertical": vertical,
            "other_s": math.tan(math.radians(obest)), "other_gain": ogain}


def backing_level(g, w, h):
    """Scanner backing brightness: the darker of the top/bottom overscan-strip
    medians (the strips above/below the paper)."""
    import statistics
    x0, x1 = w // 4, 3 * w // 4
    meds = []
    for rows in (range(0, min(24, h)), range(max(0, h - 12), h)):
        vals = [v for y in rows for v in g[y * w + x0:y * w + x1:5]]
        if vals:
            meds.append(statistics.median(vals))
    return min(meds) if meds else 255


def geometry_gray(g, w, h):
    """Copy of the page for edge finding. With the factory light curve the
    scanner backing reads ~210 (paper ~232) instead of clipping at 255; scale
    so the backing clips again, which is what the shadow detector expects.
    The backing level is the darker of the top/bottom strip medians (the
    overscan above/below the paper)."""
    b = backing_level(g, w, h)
    if b >= 250 or b < 120:
        return g
    k = 262.0 / b
    return g.translate(bytes(min(255, int(v * k)) for v in range(256)))


def _outside_is_empty(g, w, h, side, line, dpi, max_ink=0.002, raw=None, backing=255):
    """A real paper edge has only scanner backing beyond it (white in the
    geometry image). A table rule or text block has more printing beyond it.
    Checks the strip between the line (+ a few px for its shadow) and the image
    border; a strip under 0.05" wide counts as empty."""
    a, b = line[0], line[1]
    gap = max(3, dpi // 60)
    mask = bytes(1 if v < 128 else 0 for v in range(256))
    n = k = 0
    rawvals = []
    if side in ("left", "right"):
        for y in range(int(h * 0.05), int(h * 0.95), 4):
            x = int(round(a + b * y))
            lo, hi = (0, max(0, x - gap)) if side == "left" else (min(w, x + gap + 1), w)
            seg = g[y * w + lo:y * w + hi]
            k += seg.translate(mask).count(1)
            n += len(seg)
            if raw is not None and hi > lo:
                rawvals.extend(raw[y * w + lo:y * w + hi:3])
    else:
        for x in range(int(w * 0.05), int(w * 0.95), 4):
            y = int(round(a + b * x))
            lo, hi = (0, max(0, y - gap)) if side == "top" else (min(h, y + gap + 1), h)
            seg = g[x + lo * w:x + hi * w:w]
            k += seg.translate(mask).count(1)
            n += len(seg)
            if raw is not None and hi > lo:
                rawvals.extend(raw[x + lo * w:x + hi * w:3 * w])
    span = (h if side in ("left", "right") else w) * 0.9 / 4
    if n < span * dpi * 0.05:                     # strip narrower than ~0.05" on average
        return True
    if k / n > max_ink:
        return False
    # With the factory light curve the backing (~210) is darker than paper
    # (~230): a bright strip beyond the "edge" is paper margin, not backing.
    if rawvals and backing < 245:
        rawvals.sort()
        if rawvals[len(rawvals) // 2] > backing + 10:
            return False
    return True


def align_page(chans, w, h, log, label, paper_len=0, dpi=300):
    """Deskew using the paper-edge shadows, then crop to the paper."""
    g = chans[1] if len(chans) == 3 else chans[0]
    est = estimate_skew(g, w, h, dpi=dpi, detail=True)
    s = est["s"] if est else None
    sv = sh = s                                   # vertical-line / horizontal-line skew
    how = "text"
    if est:
        # The front sensor's image is slightly sheared (text lines vs vertical
        # rules differ by ~0.3 deg), so use the other orientation's angle for
        # its own direction when it is measurable and close.
        o = est["other_s"]
        if (est["other_gain"] >= 1.06 and abs(math.degrees(math.atan(o)) -
                                              math.degrees(math.atan(s))) <= 0.6):
            if est["vertical"]:
                sh = o
            else:
                sv = o
            how = "text+rules"
    if s is None:                                # blank-ish page: use the edge shadows
        lines = find_paper_lines(geometry_gray(g, w, h), w, h, dpi)
        cands = [(len(lines[k][2]) / (h / 8), lines[k][1]) for k in ("left", "right") if lines[k]]
        cands += [(len(lines[k][2]) / (w / 8), -lines[k][1]) for k in ("top", "bottom") if lines[k]]
        s = max(cands)[1] if cands else 0.0
        sv = sh = s
        how = "edges"
    lines = None
    if max(abs(sv), abs(sh)) * max(w, h) >= 1.0:
        chans = [shear_cols(shear_rows(c, w, h, sv), w, h, sh) for c in chans]
        g = chans[1] if len(chans) == 3 else chans[0]
    g = geometry_gray(g, w, h)
    raw_g = chans[1] if len(chans) == 3 else chans[0]
    bk = backing_level(raw_g, w, h)
    lines = find_paper_lines(g, w, h, dpi)
    for k in list(lines):
        if lines[k] and not _outside_is_empty(g, w, h, k, lines[k], dpi, raw=raw_g, backing=bk):
            lines[k] = None                      # e.g. a table rule when the paper edge is off-scan
    lim = int(40 * dpi / 300)
    found = [k for k in lines if lines[k]]
    # horizontal extent of the top/bottom shadow = paper width where side edges are invisible
    ext = [(min(u for u, _ in lines[k][2]), max(u for u, _ in lines[k][2]))
           for k in ("top", "bottom") if lines[k]]
    x0, x1, y0, y1 = 0, w, 0, h
    vspan = (int(h * 0.1), int(h * 0.9))
    at = lambda ln, u: ln[0] + ln[1] * u          # line position at u
    # Use each edge's outermost point over the page so a slightly non-square
    # sheet (hand-folded, trimmed) is not clipped at one end.
    if lines["left"]:
        ends_l = [at(lines["left"], u) for u in vspan]
        # slightly slanted after deskew (< 0.1"): crop at the inner point so the
        # edge shadow isn't left in; larger differences = non-square sheet, keep all
        lx = int(round(max(ends_l) if max(ends_l) - min(ends_l) < 0.1 * dpi else min(ends_l)))
        x0 = lx + _inset(g, w, h, lx, "x", 1, vspan, lim)
    elif ext:
        x0 = min(e[0] for e in ext) + 4
    if lines["right"]:
        ends_r = [at(lines["right"], u) for u in vspan]
        rx = int(round(min(ends_r) if max(ends_r) - min(ends_r) < 0.1 * dpi else max(ends_r)))
        x1 = rx - _inset(g, w, h, rx, "x", -1, vspan, lim) + 1
    elif ext:
        x1 = max(e[1] for e in ext) - 4
    hspan = (max(0, x0), min(w, x1))
    ends = (hspan[0], hspan[1] - 1)
    # Vertical: the scanner reports the measured paper length. Edges whose
    # shadow is invisible (white paper: side A bottom, side B top) are placed
    # one paper length from the visible one; a detected opposite edge is kept
    # when it agrees with the measured length to 0.15".
    top_ln, bot_ln = lines["top"], lines["bottom"]
    top = int(round(min(at(top_ln, u) for u in ends))) if top_ln else None
    bot = int(round(max(at(bot_ln, u) for u in ends))) if bot_ln else None
    if paper_len > h // 3:
        tol = 0.15 * dpi
        if top is not None and bot is not None:
            span_lo = min(at(bot_ln, u) - at(top_ln, u) for u in ends)
            span_hi = max(at(bot_ln, u) - at(top_ln, u) for u in ends)
            agree = span_lo - tol <= paper_len <= span_hi + tol
        else:
            agree = False
        if not agree:
            if label == "A" or bot is None:
                bot = top + paper_len if top is not None else None
            else:
                top = bot - paper_len
    if top is not None:
        y0 = clamp(top + _inset(g, w, h, top, "y", 1, hspan, lim), 0, h)
    if bot is not None:
        y1 = clamp(bot - _inset(g, w, h, bot, "y", -1, hspan, lim) + 1, 0, h) if 0 <= bot < h else min(h, bot)
    t = max(1, dpi // 100)                       # 0.01" safety trim for corner shadow remnants
    x0, x1, y0, y1 = min(x0 + t, w), max(x1 - t, 0), min(y0 + t, h), max(y1 - t, 0)
    if x1 - x0 < w // 3 or y1 - y0 < h // 3:
        x0, x1, y0, y1 = 0, w, 0, h
    nw, nh = x1 - x0, y1 - y0
    chans = [b"".join(c[y * w + x0:y * w + x1] for y in range(y0, y1)) for c in chans]
    log("side %s: skew %s deg (%s), edges %s, crop x %d..%d y %d..%d -> %dx%d (%.2fx%.2f in)"
        % (label, "%.2f" % math.degrees(math.atan(sh)) if math.isclose(sh, sv) else
           "%.2f/%.2f" % (math.degrees(math.atan(sh)), math.degrees(math.atan(sv))), how, "+".join(found) or "none",
           x0, x1, y0, y1, nw, nh, nw / dpi, nh / dpi))
    return chans, nw, nh


# ---- output sinks ------------------------------------------------------------
class PngSink:
    def __init__(self, out):
        self.dir = out
        os.makedirs(out, exist_ok=True)

    def add(self, page, label, w, h, ch, img, log):
        p = os.path.join(self.dir, "page%03d_%s.png" % (page, label))
        write_png(p, w, h, ch, img)
        log("wrote %s (%dx%d)" % (p, w, h))

    def close(self, log):
        pass


def jpeg_encoder():
    """-> (name, encode(w, h, ch, data, quality) -> bytes) or (None, None).
    Pillow if importable, else the libjpeg `cjpeg` tool on PATH (fed a PPM/PGM
    on stdin; on NixOS: nix shell nixpkgs#libjpeg_turbo)."""
    try:
        from PIL import Image
        import io

        def enc(w, h, ch, data, q):
            buf = io.BytesIO()
            Image.frombytes("RGB" if ch == 3 else "L", (w, h), data).save(
                buf, "JPEG", quality=q, optimize=True)
            return buf.getvalue()
        return "Pillow", enc
    except ImportError:
        pass
    import shutil
    exe = shutil.which("cjpeg")
    if exe:
        import subprocess

        def enc(w, h, ch, data, q):
            hdr = b"P%d\n%d %d\n255\n" % (6 if ch == 3 else 5, w, h)
            r = subprocess.run([exe, "-quality", str(q), "-optimize"], input=hdr + data,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            return r.stdout
        return "cjpeg", enc
    return None, None


class PdfSink:
    """Minimal streaming PDF writer: one image per page. Colour pages are
    JPEG (DCTDecode) when an encoder is available and jpeg_quality > 0,
    everything else Flate."""

    def __init__(self, path, dpi, jpeg_quality=0, log=None):
        self.path, self.dpi = path, dpi
        self.jpeg_quality, self.jpeg = jpeg_quality, None
        if jpeg_quality > 0:
            name, self.jpeg = jpeg_encoder()
            if log:
                log("colour pages: %s" % ("JPEG quality %d (%s)" % (jpeg_quality, name) if name else
                    "lossless - no JPEG encoder (install Pillow, or put cjpeg on PATH: "
                    "nix shell nixpkgs#libjpeg_turbo)"))
        if os.path.dirname(path):
            os.makedirs(os.path.dirname(path), exist_ok=True)
        self.f = open(path + ".part", "wb")
        self.offsets = []
        self.pages = []
        self.f.write(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        self._reserve()             # 1: catalog
        self._reserve()             # 2: pages

    def _reserve(self):
        self.offsets.append(None)
        return len(self.offsets)

    def _obj(self, num, body, stream=None):
        self.offsets[num - 1] = self.f.tell()
        self.f.write(b"%d 0 obj\n" % num + body)
        if stream is not None:
            self.f.write(b"\nstream\n" + stream + b"\nendstream")
        self.f.write(b"\nendobj\n")

    def add(self, page, label, w, h, ch, img, log):
        import zlib
        img_n, cont_n, page_n = self._reserve(), self._reserve(), self._reserve()
        filt, data = b"/FlateDecode", None
        if ch == 3 and self.jpeg:
            try:
                data, filt = self.jpeg(w, h, ch, img, self.jpeg_quality), b"/DCTDecode"
            except Exception as e:                      # fall back to lossless
                log("JPEG encoding failed (%s); page stored lossless" % e)
                data = None
        if data is None:
            data = zlib.compress(img, 6)
        cs = b"/DeviceRGB" if ch == 3 else b"/DeviceGray"
        self._obj(img_n, b"<< /Type /XObject /Subtype /Image /Width %d /Height %d /ColorSpace %s "
                  b"/BitsPerComponent %d /Filter %s /Length %d >>"
                  % (w, h, cs, 1 if ch == 0 else 8, filt, len(data)), data)
        pw, ph = w * 72.0 / self.dpi, h * 72.0 / self.dpi
        content = b"q %.3f 0 0 %.3f 0 0 cm /Im0 Do Q" % (pw, ph)
        self._obj(cont_n, b"<< /Length %d >>" % len(content), content)
        self._obj(page_n, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %.3f %.3f] "
                  b"/Resources << /XObject << /Im0 %d 0 R >> >> /Contents %d 0 R >>"
                  % (pw, ph, img_n, cont_n))
        self.pages.append(page_n)
        log("added sheet %d side %s to PDF (%dx%d, %.1f MB)" % (page, label, w, h, len(data) / 1e6))

    def close(self, log):
        if not self.pages:
            self.f.close()
            os.unlink(self.path + ".part")
            log("no pages scanned; no PDF written")
            return
        kids = b" ".join(b"%d 0 R" % n for n in self.pages)
        self._obj(1, b"<< /Type /Catalog /Pages 2 0 R >>")
        self._obj(2, b"<< /Type /Pages /Kids [%s] /Count %d >>" % (kids, len(self.pages)))
        xref = self.f.tell()
        self.f.write(b"xref\n0 %d\n0000000000 65535 f \n" % (len(self.offsets) + 1))
        for off in self.offsets:
            self.f.write(b"%010d 00000 n \n" % off)
        self.f.write(b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n"
                     % (len(self.offsets) + 1, xref))
        self.f.close()
        os.replace(self.path + ".part", self.path)
        log("wrote %s (%d pages)" % (self.path, len(self.pages)))


MAX_LENGTH_MODES = {"standard": 355600, "1000": 1000000, "3000": 3000000}   # micrometres


def cmd_max_length(r, a):
    """Show or set the stored maximum document length (vendor maintenance panel
    "Maximum length for paper size": Standard 356 mm / Long Document 1,000 or
    3,000 mm). Stored in the scanner: READ/SEND dtc 8C q 00 01 (0x80 bytes),
    BE32 at offset 0x10 in micrometres. INQUIRY EVPD F0 max_length follows it."""
    blk = bytearray(r.read(7, 0x80))
    cur = struct.unpack_from(">I", blk, 0x10)[0]
    if a.length:
        new = MAX_LENGTH_MODES[a.length]
        if new != cur:
            struct.pack_into(">I", blk, 0x10, new)
            r.t.execute(bytes([0x2A, 0, 0x8C, 0, 0, 1, 0, 0, 0x80, 0]), data_out=bytes(blk))
            cur = struct.unpack_from(">I", r.read(7, 0x80), 0x10)[0]
            if cur != new:
                raise ScannerError("scanner kept %d um after setting %d um" % (cur, new))
    name = {v: k for k, v in MAX_LENGTH_MODES.items()}.get(cur, "custom")
    caps = r.inquiry_ex()
    print("maximum document length: %.0f mm (%s); scanner reports %.2f in"
          % (cur / 1000.0, name, caps["max_length"] / caps["base_yres"]))
    if cur > 400000:
        print("long document mode: feed long sheets straight and by hand; jam detection is "
              "delayed (vendor warning). Pages use a lot of memory "
              "(raw data about 30 MB per metre per side in gray at 300 dpi; x3 for colour, x4 at 600 dpi).")


def cmd_button(r, a):
    try:
        while True:
            if not r.wait_button(a.btn_timeout):
                sys.exit(1)
            print("pressed", flush=True)
            if not a.loop:
                return
    except KeyboardInterrupt:
        pass


def cmd_info(r, a):
    d = r.inquiry()
    print("INQUIRY:", d.hex(" "))
    print("  vendor  :", d[8:16].decode(errors="replace"))
    print("  product :", d[16:32].decode(errors="replace"))
    print("  revision:", d[32:36].decode(errors="replace"))


def cmd_appfiles(r, a):
    files = r.app_files()
    for i, (addr, size) in enumerate(files):
        print("file %d: addr=0x%08x size=%d" % (i, addr, size))
    if a.out:
        os.makedirs(a.out, exist_ok=True)
        for i, (addr, size) in enumerate(files):
            blob = r.read_blob(addr, size)
            p = os.path.join(a.out, "appfile%d.bin" % i)
            with open(p, "wb") as f:
                f.write(blob)
            print("wrote", p, blob[:8].hex(" "))


def cmd_raw(r, a):
    cdb = bytes.fromhex(a.cdb)
    out = bytes.fromhex(a.data_out) if a.data_out else None
    d = r.t.execute(cdb, data_out=out, data_in_len=a.read, check=False)
    print("status %08x" % r.t.status)
    if d:
        print(d.hex(" "))


def main():
    ap = argparse.ArgumentParser(
        description=__doc__.split("\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""quick start:
  canon_r10.py --default-col     colour, 300 dpi, both sides, PDF; feed sheets, button to finish
  canon_r10.py --default-bw      the same in black and white
  canon_r10.py scan --help       all scan options, presets and recommended settings
  canon_r10.py max-length 1000   long document mode (sheets up to 1 m)""")
    ap.add_argument("--volume", help="mount point of ONTOUCHLITE (auto)")
    ap.add_argument("--timeout", type=float, default=90.0)
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("info", help="INQUIRY")
    p = sub.add_parser("max-length", help="show/set the maximum document length (long document mode)")
    p.add_argument("length", nargs="?", choices=sorted(MAX_LENGTH_MODES),
                   help="standard (356 mm), 1000 or 3000 (mm, long document mode)")
    p = sub.add_parser("button", help="wait for the scanner button (for scripts)")
    p.add_argument("--loop", action="store_true", help="print a line per press until Ctrl-C")
    p.add_argument("--timeout", dest="btn_timeout", type=float, default=None,
                   help="give up after N seconds (exit status 1)")
    p = sub.add_parser("appfiles", help="list/download the on-device app archives")
    p.add_argument("-o", "--out", help="directory to save archives")
    p = sub.add_parser("raw", help="send a raw CDB")
    p.add_argument("cdb", help="hex, e.g. 120000006000")
    p.add_argument("--read", type=int, default=0, help="data-in length")
    p.add_argument("--data-out", help="hex data-out payload")
    p = sub.add_parser(
        "scan", help="scan every sheet in the feeder",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""presets (also usable without 'scan', e.g. canon_r10.py --default-col):
  --default-col   colour pages, saved as JPEG (quality 85) in the PDF
  --default-bw    black-and-white 1-bit pages (threshold 170, isolated specks removed)
  Both: 300 dpi, both sides, one PDF (default name scan-YYYYmmdd-HHMMSS.pdf, or -o).
        Waits for the first sheet (button/Ctrl-C cancels), scans each sheet as it
        is fed, and finishes when the scanner button is pressed (Ctrl-C also saves).
        Blank sides are skipped (--keep-blank to keep them).
  Mode, dpi and duplex are fixed by the preset; other options still apply.

output (-o):
  canon_r10.py --default-col                       ./scan-20250101-093000.pdf
  canon_r10.py --default-col -o ~/papercut/        ~/papercut/scan-20250101-093000.pdf
  canon_r10.py --default-bw  -o ~/scans/bill.pdf   ~/scans/bill.pdf
  canon_r10.py scan -o letters.pdf                 letters.pdf
  canon_r10.py scan -o pages                       pages/page000_A.png, page000_B.png, ...
  A folder given to a preset is created if missing. An existing PDF is overwritten.

recommended image settings (on by default for every scan, presets included):
  factory light-curve correction   (--no-light-curve to disable)
  deskew + crop to the paper       (--no-align)
  auto levels: black/white point from each page  (--black-point/--white-point)
  sharpening: 0.75 at 300 dpi, 0.4 at 600 dpi   (--sharpen, 0 = off)
  colour noise (speck) removal: radius 2         (--chroma-denoise, 0 = off)
  all enhancement off: --no-enhance""")
    p.add_argument("-o", "--out", default=None, metavar="PATH",
                   help="where to save. Ending in .pdf: that PDF file. A folder (existing, "
                        "or ending in /): with a preset, scan-YYYYmmdd-HHMMSS.pdf inside it; "
                        "otherwise one PNG per side in it. Default: presets save "
                        "scan-YYYYmmdd-HHMMSS.pdf in the current folder, plain scans save PNGs "
                        "in ./scans/. See 'output' below.")
    p.add_argument("--default-col", action="store_true",
                   help="preset for colour documents (see 'presets' below)")
    p.add_argument("--default-bw", action="store_true",
                   help="preset for black-and-white text documents (see 'presets' below)")
    p.add_argument("--keep-blank", action="store_true",
                   help="presets: keep blank sides (blank-page skipping is on by default)")
    p.add_argument("--wait-paper", action="store_true",
                   help="wait for the first sheet instead of failing when the feeder is "
                        "empty (the button cancels while waiting)")
    p.add_argument("--dpi", type=int, default=300)
    p.add_argument("--mode", choices=["gray", "color", "bw", "auto"], default="gray",
                   help="bw = black-and-white text mode (gray scan, 1-bit output); "
                        "auto = scan in colour, save pages without colour as gray")
    p.add_argument("--colour-threshold", type=float, default=0.25, metavar="PCT",
                   help="auto mode: percent of the page (6x6 px blocks) that must be "
                        "coloured to keep it in colour (default 0.25)")
    p.add_argument("--jpeg-quality", type=int, default=85, metavar="Q",
                   help="PDF: store colour pages as JPEG at this quality (1-100; 0 = lossless). "
                        "Needs Pillow or the cjpeg tool")
    p.add_argument("--skip-blank", action="store_true", help="drop blank sides")
    p.add_argument("--blank-threshold", type=float, default=0.005, metavar="PCT",
                   help="--skip-blank: a side with less than this percent of ink-dark "
                        "pixels is blank (default 0.005)")
    p.add_argument("--no-despeckle", action="store_true",
                   help="bw mode: keep isolated single black pixels")
    p.add_argument("--threshold", type=int, default=170,
                   help="bw mode: gray level (after enhancement) at or above which a pixel is white")
    p.add_argument("--duplex", action="store_true", help="scan both sides")
    p.add_argument("--side-b", action="store_true", help="simplex using the other sensor")
    p.add_argument("--length", type=float, help="fixed page length in inches (default: auto)")
    p.add_argument("--single", action="store_true", help="stop after one sheet")
    p.add_argument("--button", action="store_true",
                   help="start each sheet with the scanner's button instead of on paper detection")
    p.add_argument("--feed-timeout", type=int, default=-1,
                   help="seconds to wait for the next hand-fed sheet (default: until the "
                        "scanner button or Ctrl-C ends the batch; 0 = stop when empty)")
    p.add_argument("--no-align", action="store_true", help="no deskew / crop to paper")
    p.add_argument("--no-light-curve", action="store_true",
                   help="skip the factory light-curve correction of the white reference")
    p.add_argument("--no-enhance", action="store_true", help="no levels / sharpening (raw shaded output)")
    p.add_argument("--chroma-denoise", type=int, default=2, metavar="R",
                   help="colour: smooth colour noise over a (2R+1)^2 box (0 = off, default 2)")
    p.add_argument("--sharpen", type=float, default=None,
                   help="unsharp-mask amount (0 = off; default 0.75 at 300 dpi, 0.4 at 600 dpi)")
    p.add_argument("--black-point", type=int, default=None, help="input level mapped to black (default: auto)")
    p.add_argument("--white-point", type=int, default=None,
                   help="input level mapped to white (default: auto from the paper level)")
    p.add_argument("--gamma", type=float, default=1.0, help="levels gamma (>1 darkens mid-tones)")
    p.add_argument("--order", default="BA",
                   help="duplex side order in the output (default BA: side B is the face-up side)")
    p.add_argument("--no-calibrate", action="store_true", help="skip light calibration")
    p.add_argument("--recalibrate", action="store_true", help="ignore cached calibration")
    p.add_argument("--cal-max-age", type=float, default=300,
                   help="reuse a cached calibration up to this many seconds (vendor: 300)")
    p.add_argument("--color-shift", type=lambda v: [float(x) for x in v.split(",")],
                   default=None, metavar="R,B",
                   help="vertical R,B plane correction in raw lines "
                        "(default: 0.333,-0.333 at 300 dpi, 0.25,-0.25 at 600 dpi; measured)")
    p.add_argument("--no-paper-check", action="store_true")
    p.add_argument("--keep-raw", action="store_true", help="also save the raw stream")
    p.add_argument("--no-normalize", action="store_true", help="(uncalibrated only) skip software levels")
    p.add_argument("--no-flip", action="store_true", help="keep raw line order")
    argv = sys.argv[1:]
    if any(x in ("--default-col", "--default-bw") for x in argv) and "scan" not in argv:
        argv = ["scan"] + argv                    # allow: canon_r10.py --default-col
    a = ap.parse_args(argv)
    if a.cmd == "scan":
        if a.default_col and a.default_bw:
            ap.error("--default-col and --default-bw are mutually exclusive")
        if a.default_col or a.default_bw:
            a.mode = "color" if a.default_col else "bw"
            a.dpi, a.duplex, a.wait_paper, a.single, a.button = a.dpi, True, True, False, False
            a.skip_blank = not a.keep_blank
            stamp = time.strftime("scan-%Y%m%d-%H%M%S.pdf")
            if a.out is None:
                a.out = stamp
            elif not a.out.lower().endswith(".pdf"):
                out = os.path.expanduser(a.out)
                if not (os.path.isdir(out) or a.out.endswith("/")):
                    ap.error("-o %s: with a preset give a folder (existing, or ending in /) "
                             "or a file name ending in .pdf" % a.out)
                os.makedirs(out, exist_ok=True)
                a.out = os.path.join(out, stamp)
        elif a.out is None:
            a.out = "scans"

    try:
        with FileTransport(a.volume, a.timeout, a.verbose) as t:
            {"info": cmd_info, "appfiles": cmd_appfiles, "raw": cmd_raw,
             "scan": cmd_scan, "button": cmd_button,
             "max-length": cmd_max_length}[a.cmd](R10(t), a)
    except ScannerError as e:
        sys.exit("error: %s" % e)


if __name__ == "__main__":
    main()
