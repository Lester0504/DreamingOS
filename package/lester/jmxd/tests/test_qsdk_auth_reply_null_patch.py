#!/usr/bin/env python3
"""Offline instruction tests; private native binary/core are CLI inputs.

Requires unicorn and pyelftools in an isolated external environment. No router,
driver, hostapd process, or network connection is used by this test.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, replace
import importlib.util
import io
import itertools
import json
from pathlib import Path
import struct
import tempfile


PATCHER_PATH = Path(__file__).resolve().parents[1] / "tools/qsdk_auth_reply_null_patch.py"
SPEC = importlib.util.spec_from_file_location("qsdk_null_patch", PATCHER_PATH)
patcher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(patcher)

ENTRY = 0x1EF0D0
FAULT = 0x1EF178
CORE_BASE = 0x5568630000
CORE_FRAME_SP = 0x7FEF425BD0
SCRATCH = 0x6000000000
RETURN = SCRATCH + 0xE0000
STUBS = SCRATCH + 0xF0000
GOT = {
    0x4ED340: "ml_response",
    0x4EDA90: "zalloc",
    0x4EA5A8: "wpabuf_free",
    0x4E9A58: "memcpy",
    0x4EFFB0: "log",
    0x4EF440: "free",
    0x4EA7D8: "send",
}
ML_DATA = bytes.fromhex("ff036b0000")
OWN_ADDR = bytes.fromhex("021122334455")
PEER_ADDR = bytes.fromhex("0266778899aa")


@dataclass(frozen=True)
class Case:
    station: bool = True
    ap_mld: bool = False
    sta_mld: bool = False
    flag_538: bool = False
    flag_539: bool = False
    algorithm: int = 0
    transaction: int = 2
    status: int = 1
    immediate: int = 0
    saved_reply: bool = False
    ies: bytes = bytes.fromhex("dd020102")
    fail_ml: bool = False
    fail_alloc: bool = False
    fail_send: bool = False

    def uses_ml(self) -> bool:
        predicate = self.ap_mld and self.sta_mld
        return self.station and (
            (predicate and not self.flag_539)
            or (not predicate and self.flag_538)
        )

    def retains_reply(self) -> bool:
        return (
            self.station
            and self.immediate == 2
            and self.algorithm == 3
            and self.transaction == 1
            and self.status in (0, 126, 127)
        )


def elf_loads(data: bytes) -> tuple[dict, list]:
    from elftools.elf.elffile import ELFFile

    elf = ELFFile(io.BytesIO(data))
    assert elf.elfclass == 64 and elf.little_endian
    assert elf["e_machine"] == "EM_AARCH64"
    loads = [
        (s["p_vaddr"], s["p_memsz"], s.data(), s["p_flags"])
        for s in elf.iter_segments()
        if s["p_type"] == "PT_LOAD"
    ]
    return dict(elf.header), loads


class ReplyMachine:
    """Execute the native reply/helper instructions, mocking only call-outs."""

    def __init__(self, image, case: Case, *, base=0x10000000, core=None):
        import unicorn
        from unicorn import arm64_const

        self.api = unicorn
        self.reg = arm64_const
        self.uc = unicorn.Uc(unicorn.UC_ARCH_ARM64, unicorn.UC_MODE_ARM)
        self.pages = set()
        self.base, self.case = base, case
        self.calls, self.frames = [], []
        self.invalid = None
        self.checkpoint = None
        for address, size, data, _ in image:
            self.map(base + address, size)
            self.uc.mem_write(base + address, data)
        if core is not None:
            for address, size, data, _ in core:
                assert address + size <= SCRATCH or address >= SCRATCH + 0x100000
                self.map(address, size)
                self.uc.mem_write(address, data)
            # Core dumps omit file-backed text. Always execute the input image.
            for address, _, data, flags in image:
                if flags & 1:
                    self.uc.mem_write(base + address, data)
        self.map(SCRATCH, 0x100000)
        self.hapd = SCRATCH + 0x1000
        self.conf = SCRATCH + 0x2000
        self.sta = SCRATCH + 0x4000 if case.station else 0
        self.output = SCRATCH + 0x8000
        self.ml = SCRATCH + 0x7000
        self.put64(self.ml, len(ML_DATA), len(ML_DATA), self.ml + 0x100)
        self.uc.mem_write(self.ml + 0x100, ML_DATA)

        if core is None:
            self.prepare_synthetic()
        else:
            self.prepare_core()
        self.uc.reg_write(self.reg.UC_ARM64_REG_SP, self.initial_sp)
        self.uc.reg_write(self.reg.UC_ARM64_REG_X19, 0x19191919)
        self.uc.reg_write(self.reg.UC_ARM64_REG_X20, 0x20202020)
        self.uc.reg_write(self.reg.UC_ARM64_REG_X29, 0x29292929)
        self.uc.reg_write(self.reg.UC_ARM64_REG_X30, RETURN)
        for index, value in enumerate(self.args):
            self.setx(index, value)

        self.stub_names = {}
        for index, (slot, name) in enumerate(GOT.items()):
            address = STUBS + index * 4
            self.put64(base + slot, address)
            self.uc.mem_write(address, bytes.fromhex("c0035fd6"))  # ret
            self.stub_names[address] = name
        self.uc.hook_add(
            unicorn.UC_HOOK_CODE, self.on_stub, begin=STUBS, end=STUBS + 0xFF
        )
        self.uc.hook_add(
            unicorn.UC_HOOK_CODE,
            self.on_checkpoint,
            begin=base + patcher.PATCH_OFFSET + 4,
            end=base + patcher.PATCH_OFFSET + 4,
        )
        self.uc.hook_add(unicorn.UC_HOOK_MEM_INVALID, self.on_invalid)

    def map(self, address, size):
        end = (address + size + 0xFFF) & ~0xFFF
        start = address & ~0xFFF
        missing = sorted(set(range(start, end, 0x1000)) - self.pages)
        for _, group in itertools.groupby(
            enumerate(missing), key=lambda item: item[1] - item[0] * 0x1000
        ):
            run = [page for _, page in group]
            self.uc.mem_map(run[0], len(run) * 0x1000)
        self.pages.update(missing)

    def put64(self, address, *values):
        self.uc.mem_write(address, struct.pack("<" + "Q" * len(values), *values))

    def get64(self, address):
        return struct.unpack("<Q", self.uc.mem_read(address, 8))[0]

    def get16(self, address):
        return struct.unpack("<H", self.uc.mem_read(address, 2))[0]

    def x(self, index):
        return self.uc.reg_read(getattr(self.reg, f"UC_ARM64_REG_X{index}"))

    def setx(self, index, value):
        self.uc.reg_write(getattr(self.reg, f"UC_ARM64_REG_X{index}"), value)

    def prepare_synthetic(self):
        case = self.case
        self.put64(self.hapd + 0x10, self.conf)
        self.uc.mem_write(self.hapd + 0x24, OWN_ADDR)
        self.uc.mem_write(self.conf + 0xBB2, bytes([case.ap_mld]))
        self.uc.mem_write(self.conf + 0x904, struct.pack("<I", case.immediate))
        if self.sta:
            for offset, value in (
                (0x320, case.sta_mld),
                (0x538, case.flag_538),
                (0x539, case.flag_539),
            ):
                self.uc.mem_write(self.sta + offset, bytes([value]))
            if case.saved_reply:
                saved = SCRATCH + 0x5200
                self.uc.mem_write(saved, b"\xb0" + bytes(29))
                self.put64(self.sta + 0x308, saved, 30)
        dst, ies = SCRATCH + 0x5000, SCRATCH + 0x5100
        self.uc.mem_write(dst, PEER_ADDR)
        self.uc.mem_write(ies, case.ies)
        self.initial_sp = SCRATCH + 0x60000
        self.put64(self.initial_sp, 0)
        self.args = (
            self.hapd, self.sta, dst, case.algorithm, case.transaction,
            case.status, ies if case.ies else 0, len(case.ies),
        )

    def prepare_core(self):
        frame = CORE_FRAME_SP
        self.args = (
            self.get64(frame + 0x78), self.get64(frame + 0x70),
            self.get64(frame + 0x68), self.get16(frame + 0x66),
            self.get16(frame + 0x64), self.get16(frame + 0x62),
            self.get64(frame + 0x58), self.get64(frame + 0x50),
        )
        assert self.args[1] == 0 and self.args[3:6] == (0, 2, 1), (
            "core does not match the recorded NULL-station failure frame"
        )
        self.hapd, self.sta = self.args[:2]
        self.initial_sp = frame + 0xB0

    def on_checkpoint(self, uc, address, size, _):
        self.checkpoint = tuple(self.x(i) for i in range(31)) + (
            uc.reg_read(self.reg.UC_ARM64_REG_SP),
            uc.reg_read(self.reg.UC_ARM64_REG_NZCV),
        )

    def on_invalid(self, uc, access, address, size, value, _):
        self.invalid = (uc.reg_read(self.reg.UC_ARM64_REG_PC), address, size)
        return False

    def on_stub(self, uc, address, size, _):
        name = self.stub_names[address]
        a, b, c = self.x(0), self.x(1), self.x(2)
        if name == "ml_response":
            self.calls.append((name,))
            self.setx(0, 0 if self.case.fail_ml else self.ml)
        elif name == "zalloc":
            assert a <= 0x2000
            self.calls.append((name, a))
            uc.mem_write(self.output, bytes(a))
            self.setx(0, 0 if self.case.fail_alloc else self.output)
        elif name == "memcpy":
            assert c <= 0x2000
            uc.mem_write(a, bytes(uc.mem_read(b, c)))
            self.setx(0, a)
        elif name == "send":
            assert c <= 0x2000
            self.frames.append(bytes(uc.mem_read(b, c)))
            self.calls.append((name, a, c, *(self.x(i) for i in range(3, 7))))
            self.setx(0, 0xFFFFFFFF if self.case.fail_send else 0)
        elif name in ("free", "wpabuf_free"):
            self.calls.append((name, a))
        elif name == "log":
            self.calls.append((name, a))
        else:
            raise AssertionError(f"unhandled call-out: {name}")

    def run(self):
        try:
            self.uc.emu_start(self.base + ENTRY, RETURN, count=10000)
        except self.api.UcError:
            if self.invalid is None:
                raise
        if self.invalid is not None:
            return {"fault": self.invalid}
        assert self.uc.reg_read(self.reg.UC_ARM64_REG_PC) == RETURN, "did not return"
        assert self.uc.reg_read(self.reg.UC_ARM64_REG_SP) == self.initial_sp
        assert (self.x(19), self.x(20), self.x(29)) == (
            0x19191919, 0x20202020, 0x29292929
        ), "callee-saved registers changed"
        return {
            "result": self.x(0) & 0xFFFFFFFF,
            "frames": self.frames,
            "calls": self.calls,
            "station": bytes(self.uc.mem_read(self.sta, 0x600)) if self.sta else b"",
            "retained": (
                bytes(self.uc.mem_read(self.output, self.get64(self.sta + 0x310)))
                if self.sta and self.case.retains_reply() else b""
            ),
        }


def verify_patch(original):
    patched = patcher.transform(original)
    assert patcher.transform(patched, reverse=True) == original
    assert len(original) == len(patched)
    changed = [i for i, (a, b) in enumerate(zip(original, patched)) if a != b]
    assert all(
        patcher.PATCH_OFFSET <= index < patcher.PATCH_OFFSET + 4 for index in changed
    )
    assert original[patcher.PATCH_OFFSET : patcher.PATCH_OFFSET + 4] != (
        patched[patcher.PATCH_OFFSET : patcher.PATCH_OFFSET + 4]
    )
    for invalid, reverse in (
        (original[:-1] + bytes([original[-1] ^ 1]), False),
        (patched, False),
        (original, True),
        (b"", False),
    ):
        try:
            patcher.transform(invalid, reverse=reverse)
        except ValueError:
            pass
        else:
            raise AssertionError("unexpected binary accepted")
    with tempfile.TemporaryDirectory(prefix="qsdk-null-patch-") as temporary:
        source, output = Path(temporary) / "original", Path(temporary) / "patched"
        source.write_bytes(original)
        patcher.write_copy(source, output)
        assert output.read_bytes() == patched and source.read_bytes() == original
        for destination in (source, output):
            try:
                patcher.write_copy(source, destination)
            except FileExistsError:
                pass
            else:
                raise AssertionError("existing output overwritten")
        assert source.read_bytes() == original and output.read_bytes() == patched
    return patched


def verify_frame(frame, algorithm, transaction, status, own, peer, suffix):
    assert frame[:2] == b"\xb0\x00"
    assert frame[4:10] == peer and frame[10:16] == own and frame[16:22] == own
    assert struct.unpack("<HHH", frame[24:30]) == (algorithm, transaction, status)
    assert frame[30:] == suffix


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--core", type=Path, help="private core from the recorded crash")
    args = parser.parse_args()
    original = args.binary.read_bytes()
    patched = verify_patch(original)
    _, old_image = elf_loads(original)
    _, new_image = elf_loads(patched)
    counts = {
        "original_null_faults": 0, "patched_null_replies": 0,
        "nonnull_equivalence": 0, "failure_paths": 0, "core_replays": 0,
    }

    for ap_mld in (False, True):
        old = ReplyMachine(old_image, Case(station=False, ap_mld=ap_mld)).run()
        assert old["fault"] == (0x10000000 + FAULT, 0x538, 1)
        counts["original_null_faults"] += 1
        for algorithm, transaction, status in itertools.product(
            (0, 3), (1, 2), (1, 13, 76, 127)
        ):
            case = Case(
                station=False, ap_mld=ap_mld, algorithm=algorithm,
                transaction=transaction, status=status, immediate=2,
                ies=b"" if status == 1 else Case.ies,
            )
            machine = ReplyMachine(new_image, case)
            result = machine.run()
            assert result["result"] == 0 and len(result["frames"]) == 1
            assert machine.checkpoint is None
            assert ("ml_response",) not in result["calls"]
            verify_frame(
                result["frames"][0], algorithm, transaction, status,
                OWN_ADDR, PEER_ADDR, case.ies,
            )
            counts["patched_null_replies"] += 1

    auth_cases = [
        (0, 2, 1, 0, False), (3, 1, 0, 2, False),
        (3, 1, 126, 2, False), (3, 1, 127, 2, False),
        (3, 1, 1, 2, False), (3, 2, 0, 2, False), (3, 2, 0, 2, True),
    ]
    for ap_mld, sta_mld, f538, f539 in itertools.product((False, True), repeat=4):
        for algorithm, transaction, status, immediate, saved in auth_cases:
            case = Case(
                ap_mld=ap_mld, sta_mld=sta_mld, flag_538=f538, flag_539=f539,
                algorithm=algorithm, transaction=transaction, status=status,
                immediate=immediate, saved_reply=saved,
            )
            before, after = ReplyMachine(old_image, case), ReplyMachine(new_image, case)
            expected, actual = before.run(), after.run()
            assert actual == expected, f"non-NULL behavior changed: {case}"
            assert before.checkpoint == after.checkpoint
            assert actual["result"] == 0
            assert actual["calls"].count(("ml_response",)) == int(case.uses_ml())
            frame = actual["retained"] if case.retains_reply() else actual["frames"][-1]
            verify_frame(
                frame, algorithm, transaction, status, OWN_ADDR, PEER_ADDR,
                case.ies + (ML_DATA if case.uses_ml() else b""),
            )
            counts["nonnull_equivalence"] += 1
        # The one-instruction branch must remain position-independent.
        case = Case(ap_mld=ap_mld, sta_mld=sta_mld, flag_538=f538, flag_539=f539)
        before = ReplyMachine(old_image, case, base=CORE_BASE)
        after = ReplyMachine(new_image, case, base=CORE_BASE)
        assert before.run() == after.run() and before.checkpoint == after.checkpoint
        counts["nonnull_equivalence"] += 1

    for station, use_ml in ((False, False), (True, False), (True, True)):
        base_case = Case(station=station, ap_mld=use_ml, sta_mld=use_ml)
        for failure in ("fail_alloc", "fail_send", "fail_ml"):
            if failure == "fail_ml" and not use_ml:
                continue
            case = replace(base_case, **{failure: True})
            result = ReplyMachine(new_image, case).run()
            assert result["result"] == (1 if case.fail_send else 0xFFFFFFFF)
            if case.fail_send:
                assert len(result["frames"]) == 1
                assert ("free", SCRATCH + 0x8000) in result["calls"]
                verify_frame(
                    result["frames"][0], 0, 2, 1, OWN_ADDR, PEER_ADDR,
                    case.ies + (ML_DATA if use_ml else b""),
                )
            else:
                assert not result["frames"]
            if station:
                assert ReplyMachine(old_image, case).run() == result
            counts["failure_paths"] += 1

    if args.core:
        _, core = elf_loads(args.core.read_bytes())
        case = Case(station=False)
        before = ReplyMachine(old_image, case, base=CORE_BASE, core=core)
        assert before.run()["fault"] == (CORE_BASE + FAULT, 0x538, 1)
        after = ReplyMachine(new_image, case, base=CORE_BASE, core=core)
        result = after.run()
        assert result["result"] == 0 and len(result["frames"]) == 1
        assert ("ml_response",) not in result["calls"]
        hapd, _, dst, algorithm, transaction, status, ies, length = after.args
        verify_frame(
            result["frames"][0], algorithm, transaction, status,
            bytes(after.uc.mem_read(hapd + 0x24, 6)),
            bytes(after.uc.mem_read(dst, 6)),
            bytes(after.uc.mem_read(ies, length)) if length else b"",
        )
        counts["core_replays"] = 2
    print(json.dumps({
        "ok": True,
        "scope": "native reply/helper instructions; external calls and driver mocked",
        "cases": counts,
        "input_sha256": patcher.ORIGINAL_SHA256,
        "output_sha256": patcher.PATCHED_SHA256,
        "hardware_tested": False,
    }, indent=2))


if __name__ == "__main__":
    main()
