"""p2.lua under real tshark: the sample dissects, and hostile frames cannot make it
raise, mis-frame or hang.

Until 2.12.0 nothing in CI ran the dissector. The tests that mention p2.lua read it
as text; the plugin people install was the one deliverable never executed. It
nearly hid a second failure, too: a Wireshark profile that lists `p2` in
`disabled_protos` loads the plugin and then never calls it, so "the plugin loads"
proves nothing. Every run here therefore uses an empty configuration directory,
loads p2.lua explicitly, and counts dissected frames.

The hostile frames are seeded mutations of the synthetic sample capture, each on
its own TCP stream so one cannot swallow another in reassembly. A planted
`error()` in a copy of p2.lua must be seen, so a clean result means something.

Every file tshark reads is first copied into pytest's temporary directory. On
Ubuntu 26.04 the packaged tshark runs under an AppArmor profile that refused to
open `p2.lua` in the checkout and the personal plugin folder
`~/.local/lib/wireshark/plugins/`, while files under /tmp loaded (CI, 2026-11-20:
kernel DENIED records for exactly those paths). Staging keeps the test about
p2.lua rather than about a distribution's confinement policy.

Skips when tshark is not on PATH, unless P2_REQUIRE_TSHARK is set: the CI job
that installs tshark sets it, so a missing tshark there fails instead of passing
quietly.
"""
from __future__ import annotations

import os
import random
import re
import shutil
import struct
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
LUA = ROOT / "p2.lua"
SAMPLE = ROOT / "captures" / "p2_virtual_pxc_sample.pcap"
TSHARK = shutil.which("tshark")

if TSHARK is None:
    if os.environ.get("P2_REQUIRE_TSHARK"):
        raise RuntimeError("P2_REQUIRE_TSHARK is set but tshark is not on PATH")
    pytest.skip("tshark not on PATH", allow_module_level=True)

SAMPLE_P2_FRAMES = 47           # captures/README.md
MUTANTS_PER_FRAME = 40
SEED = 20261120
TIMEOUT_S = 180


@pytest.fixture(scope="module")
def staged(tmp_path_factory):
    """Copies of p2.lua and the sample capture where a confined tshark may read
    them (see the module docstring)."""
    d = tmp_path_factory.mktemp("staged")
    lua, sample = d / "p2.lua", d / SAMPLE.name
    shutil.copyfile(LUA, lua)
    shutil.copyfile(SAMPLE, sample)
    return lua, sample


@pytest.fixture(scope="module")
def config_dir(tmp_path_factory):
    """An empty Wireshark configuration: no profile can disable p2, and no
    personal copy of the plugin can collide with the one loaded here."""
    return tmp_path_factory.mktemp("wireshark_config")


def tshark(config_dir, capture, *args, lua, timeout=TIMEOUT_S):
    env = dict(os.environ, WIRESHARK_CONFIG_DIR=str(config_dir))
    res = subprocess.run([TSHARK, "-X", "lua_script:%s" % lua, "-r", str(capture), *args],
                         capture_output=True, timeout=timeout, env=env)
    return res.returncode, (res.stdout + res.stderr).decode("utf-8", "replace")


def lua_errors(out):
    return [line for line in out.splitlines() if "Lua Error" in line]


def p2_trees(out):
    return sum(1 for line in out.splitlines() if line.startswith("Siemens P2"))


# ---------------------------------------------------------------------------
# The sample, and a planted error

def test_the_sample_dissects_as_documented(config_dir, staged):
    lua, sample = staged
    rc, out = tshark(config_dir, sample, "-Y", "p2", "-T", "fields", "-e", "frame.number",
                     lua=lua)
    assert rc == 0, out[-2000:]
    assert len([l for l in out.splitlines() if l.strip().isdigit()]) == SAMPLE_P2_FRAMES

    rc, out = tshark(config_dir, sample, "-V", lua=lua)
    assert rc == 0
    assert lua_errors(out) == []
    assert "[Malformed Packet" not in out


def test_a_planted_error_is_seen(config_dir, staged, tmp_path):
    """The check the fuzz test relies on has to be able to fail."""
    src = LUA.read_text(encoding="utf-8")
    m = re.search(r"^function p2\.dissector\([^)]*\)\n", src, re.M)
    assert m, "p2.dissector's definition moved; update this control"
    planted = tmp_path / "p2_planted.lua"
    planted.write_text(src[:m.end()]
                       + '  if tvb:len() > 100 then error("planted control") end\n'
                       + src[m.end():], encoding="utf-8")
    rc, out = tshark(config_dir, staged[1], "-V", lua=planted)
    assert any("planted control" in line for line in lua_errors(out))


# ---------------------------------------------------------------------------
# Hostile frames

def _read_pcap(path):
    raw = path.read_bytes()
    head, off, frames = raw[:24], 24, []
    while off + 16 <= len(raw):
        incl = struct.unpack_from("<I", raw, off + 8)[0]
        frames.append(raw[off + 16:off + 16 + incl])
        off += 16 + incl
    return head, frames


def _mutate(rng, p):
    p = bytearray(p)
    k = rng.randrange(9)
    if k == 0:                                      # the length prefix
        v = rng.choice([0, 1, 12, 13, 16, 17, 18, len(p) - 1, len(p) + 1, 0xFFFF,
                        0x10000, 0x10001, 0x7FFFFFFF, 0xFFFFFFFF])
        p[0:4] = struct.pack(">I", v)
    elif k == 1:                                    # msg_type
        p[4:8] = struct.pack(">I", rng.choice([0, 1, 13, 0x33, 0xFF, 0xFFFF, 0xFFFFFFFF]))
    elif k == 2:                                    # direction byte
        p[12] = rng.randrange(256)
    elif k == 3:                                    # routing slots lose their NULs
        for i in range(13, min(len(p), 80)):
            if p[i] == 0 and rng.random() < 0.7:
                p[i] = 0x41
    elif k == 4:                                    # bytes flipped in the body
        for _ in range(rng.randint(1, 6)):
            p[rng.randrange(13, len(p))] = rng.randrange(256)
    elif k == 5:                                    # truncated; prefix still claims more
        p = p[:rng.randint(13, len(p) - 1)]
    elif k == 6:                                    # truncated; prefix agrees
        p = p[:rng.randint(13, len(p))]
        p[0:4] = struct.pack(">I", len(p))
    elif k == 7:                                    # junk appended; prefix agrees
        p += bytes(rng.randrange(256) for _ in range(rng.randint(1, 600)))
        p[0:4] = struct.pack(">I", len(p))
    else:                                           # lengths inside the body maxed out
        for _ in range(rng.randint(1, 4)):
            p[rng.randrange(13, len(p))] = 0xFF
    return bytes(p)


@pytest.fixture(scope="module")
def hostile_capture(tmp_path_factory):
    head, frames = _read_pcap(SAMPLE)
    rng = random.Random(SEED)
    records, port = [], 20000
    for f in frames:
        t = 14 + (f[14] & 0x0F) * 4
        sport, dport = struct.unpack_from(">HH", f, t)
        doff = (f[t + 12] >> 4) * 4
        payload = f[t + doff:]
        if 5033 not in (sport, dport) or len(payload) < 17:
            continue
        for _ in range(MUTANTS_PER_FRAME):
            port += 1
            body = _mutate(rng, payload)
            tcp = bytearray(f[t:t + doff])
            if dport == 5033:                       # client side: new source port
                tcp[0:2] = struct.pack(">H", port)
            else:                                   # panel side: new destination port
                tcp[2:4] = struct.pack(">H", port)
            ip = bytearray(f[14:t])
            ip[2:4] = struct.pack(">H", len(ip) + len(tcp) + len(body))
            records.append(f[:14] + bytes(ip) + bytes(tcp) + body)
    path = tmp_path_factory.mktemp("hostile") / "p2_hostile.pcap"
    with open(path, "wb") as fh:
        fh.write(head)
        for i, r in enumerate(records):
            fh.write(struct.pack("<IIII", 1767225600 + i, 0, len(r), len(r)) + r)
    return path, len(records)


def test_hostile_frames_never_raise_or_hang(config_dir, staged, hostile_capture):
    path, n = hostile_capture
    assert n == SAMPLE_P2_FRAMES * MUTANTS_PER_FRAME
    rc, out = tshark(config_dir, path, "-V", lua=staged[0])   # a hang is a TimeoutExpired
    assert rc == 0, out[-2000:]
    assert p2_trees(out) > n // 2, "the dissector did not engage; the zeros below would mean nothing"
    assert lua_errors(out) == [], sorted(set(lua_errors(out)))[:10]
    assert "[Malformed Packet" not in out


def test_analyze_pcap_survives_the_same_frames(config_dir, hostile_capture):
    path, _ = hostile_capture
    env = dict(os.environ, WIRESHARK_CONFIG_DIR=str(config_dir))
    res = subprocess.run([sys.executable, str(ROOT / "analyze_pcap.py"), str(path), "--decode"],
                         capture_output=True, timeout=TIMEOUT_S, env=env, cwd=str(ROOT))
    out = (res.stdout + res.stderr).decode("utf-8", "replace")
    assert res.returncode == 0, out[-2000:]
    assert "Traceback" not in out
    assert "frames extracted" in out
