#!/usr/bin/env python3
"""FortiTatake OS build driver. Runs inside the FortiTatake-Builder WSL2 distro.

FortiTatake (the Windows app) starts it and reads its stdout: every line starting with
"FTK " is one JSON event for the build screen; everything else is raw log.

    ftkbuild.py setup                       (as root) install build tools, create user ftk
    ftkbuild.py build --arch x86_64 ...     (as ftk) build one variant, resumable

Resumable by design: downloads continue from the last byte (.part files), Buildroot
skips packages it already finished, and a journal lets the screen show where it resumes.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.request

BUILDROOT = "buildroot-2026.02.3"
BUILDROOT_URL = "https://buildroot.org/downloads/" + BUILDROOT + ".tar.xz"
BUILDROOT_SHA256 = "5a59e7501b0b4ec52c41f4bfa79412320e0b37eae5f719605a258e8d0c6fc7fb"

HOME = os.path.expanduser("~")
WS = os.path.join(HOME, "ftkos")
DL = os.path.join(WS, "dl")

APT = ("build-essential gcc g++ make sed binutils diffutils bash patch gzip bzip2 perl tar "
       "cpio unzip rsync file bc findutils wget curl python3 libncurses-dev git ca-certificates "
       "xz-utils lz4 libelf-dev flex bison")

_lock = threading.Lock()


def ev(kind, **kw):
    kw["ev"] = kind
    kw["t"] = round(time.time(), 3)
    with _lock:
        sys.stdout.write("FTK " + json.dumps(kw) + "\n")
        sys.stdout.flush()


def log(line):
    with _lock:
        sys.stdout.write(line.rstrip("\n") + "\n")
        sys.stdout.flush()


def fail(msg):
    ev("error", msg=msg)
    sys.exit(1)


# ---------------------------------------------------------------- setup (as root)

def cmd_setup(_a):
    if os.geteuid() != 0:
        fail("setup must run as root")
    ev("phase", phase="setup", state="start", label="Preparing the build environment")
    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
    for step, argv in (("Updating package lists", ["apt-get", "update", "-q"]),
                       ("Installing build tools", ["apt-get", "install", "-y", "-q"] + APT.split())):
        ev("step", label=step)
        p = subprocess.run(argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in p.stdout.splitlines()[-30:]:
            log(line)
        if p.returncode != 0:
            fail(step + " failed")
    if subprocess.run(["id", "ftk"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
        subprocess.run(["useradd", "-m", "-s", "/bin/bash", "ftk"], check=True)
    # Builds run as ftk by default.
    with open("/etc/wsl.conf", "w") as f:
        f.write("[user]\ndefault=ftk\n[interop]\nappendWindowsPath=false\n")
    ev("phase", phase="setup", state="done", label="Build environment ready")


# ---------------------------------------------------------------- downloads

def fetch(url, dest, label, sha256=None):
    """Download url to dest, resuming a .part file; verify sha256 when given."""
    if os.path.exists(dest):
        if not sha256 or sha_file(dest) == sha256:
            return True
        os.remove(dest)
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    part = dest + ".part"
    have = os.path.getsize(part) if os.path.exists(part) else 0
    req = urllib.request.Request(url, headers={"User-Agent": "FortiTatake-builder"})
    if have:
        req.add_header("Range", "bytes=%d-" % have)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            if have and r.status != 206:
                have = 0  # server ignored the range: start over
            total = r.length + have if r.length is not None else None
            mode = "ab" if have else "wb"
            done, last = have, 0
            with open(part, mode) as f:
                while True:
                    chunk = r.read(1 << 16)
                    if not chunk:
                        break
                    f.write(chunk)
                    done += len(chunk)
                    now = time.time()
                    if now - last > 0.25:
                        ev("dl", file=label, done=done, total=total)
                        last = now
            ev("dl", file=label, done=done, total=total or done)
    except Exception as e:  # noqa: BLE001
        log("download %s from %s failed: %s" % (label, url, e))
        return False
    if sha256 and sha_file(part) != sha256:
        os.remove(part)
        log("checksum mismatch for " + label)
        return False
    os.replace(part, dest)
    ev("dl_ok", file=label)
    return True


def sha_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def uri_to_url(uri, source):
    # show-info uris look like "https+https://host/path" or "https|urlencode+https://...".
    method, _, base = uri.partition("+")
    if method.split("|")[0] not in ("http", "https", "ftp"):
        return None
    return base.rstrip("/") + "/" + source


def prefetch_sources(info):
    """Download every source Buildroot will need, resumably, before it asks for them."""
    jobs = []
    for name, p in sorted(info.items()):
        for d in p.get("downloads") or []:
            src = d.get("source")
            if not src:
                continue
            dest = os.path.join(DL, p.get("dl_dir") or name, src)
            urls = [u for u in (uri_to_url(x, src) for x in d.get("uris", [])) if u]
            if urls:
                jobs.append((src, dest, urls))
    seen = set()
    jobs = [j for j in jobs if not (j[1] in seen or seen.add(j[1]))]
    ev("sources", total=len(jobs), ready=sum(1 for j in jobs if os.path.exists(j[1])))
    for i, (src, dest, urls) in enumerate(jobs):
        if os.path.exists(dest):
            continue
        ev("source", index=i + 1, total=len(jobs), file=src)
        for u in urls:
            if fetch(u, dest, src):
                break
        else:
            log("could not prefetch %s; Buildroot will try again" % src)
    ev("sources", total=len(jobs), ready=sum(1 for j in jobs if os.path.exists(j[1])))


# ---------------------------------------------------------------- build

TOOLCHAIN = {"host-gcc-initial", "host-gcc-final", "host-binutils", "musl", "host-gmp", "host-mpfr",
             "host-mpc", "linux-headers", "host-m4", "toolchain-buildroot", "host-isl", "musl-compat-headers"}
KERNEL = {"linux", "host-lz4", "host-libelf", "host-zlib", "host-zstd"}
PROTOCOLS = {"dnsmasq", "lighttpd", "mbedtls", "dropbear", "libcurl", "tcpdump", "libpcap", "mstpd",
             "lldpd", "libevent", "conntrack-tools", "libnetfilter_conntrack", "libnetfilter_cttimeout",
             "libnetfilter_cthelper", "libnetfilter_queue", "libnfnetlink", "zlib", "pcre2", "xxhash"}
WEIGHT = {"host-gcc-final": 14, "host-gcc-initial": 8, "host-binutils": 5, "linux": 14, "musl": 2,
          "busybox": 2, "host-gmp": 2, "host-mpfr": 2, "host-erofs-utils": 1}
PROTO_LABEL = {"dnsmasq": "DHCP and DNS", "lighttpd": "HTTPS (lighttpd)", "mbedtls": "TLS",
               "dropbear": "SSH", "libcurl": "HTTP client", "tcpdump": "Packet capture",
               "mstpd": "RSTP", "lldpd": "LLDP", "conntrack-tools": "Connection tracking"}

RETIRE = [("CONFIG_MODULES", "loadable modules"), ("CONFIG_USB_SUPPORT", "USB"), ("CONFIG_SOUND", "sound"),
          ("CONFIG_DRM", "graphics"), ("CONFIG_FB", "framebuffer"), ("CONFIG_WLAN", "wireless"),
          ("CONFIG_BT", "Bluetooth"), ("CONFIG_INPUT", "input devices"), ("CONFIG_HID", "HID"),
          ("CONFIG_EXT4_FS", "ext4"), ("CONFIG_NFS_FS", "NFS"), ("CONFIG_SWAP", "swap"),
          ("CONFIG_SCSI", "SCSI"), ("CONFIG_ATA", "SATA"), ("CONFIG_WIRELESS", "802.11"),
          ("CONFIG_MEDIA_SUPPORT", "media"), ("CONFIG_SECURITY", "LSMs"), ("CONFIG_AUDIT", "audit")]
KEEP = [("CONFIG_NET_NS", "namespaces"), ("CONFIG_VETH", "veth"), ("CONFIG_BRIDGE_VLAN_FILTERING", "VLAN bridges"),
        ("CONFIG_NF_TABLES", "nftables"), ("CONFIG_NF_CONNTRACK", "conntrack"), ("CONFIG_NF_NAT", "NAT"),
        ("CONFIG_XFRM_INTERFACE", "XFRM"), ("CONFIG_NET_SCH_NETEM", "netem"), ("CONFIG_NET_VRF", "VRF"),
        ("CONFIG_EROFS_FS", "EROFS"), ("CONFIG_VIRTIO_CONSOLE", "virtio console"),
        ("CONFIG_NF_CONNTRACK_SIP", "SIP helper"), ("CONFIG_VLAN_8021Q", "802.1Q")]

LINE = re.compile(r"^>>> (\S+) (\S*) (.+?)\s*$")
ANSI = re.compile(r"\x1b\[[0-9;]*m")


def phase_of(pkg):
    if pkg in TOOLCHAIN or (pkg.startswith("host-gcc")):
        return "toolchain"
    if pkg in KERNEL:
        return "kernel"
    if pkg in PROTOCOLS:
        return "protocols"
    if pkg.startswith("host-"):
        return "toolchain"
    return "core"


def kernel_report(path):
    try:
        cfg = open(path).read()
    except OSError:
        return
    on = set(re.findall(r"^(CONFIG_\w+)=[ym]", cfg, re.M))
    kept = len(on)
    retired = len(re.findall(r"^# CONFIG_\w+ is not set", cfg, re.M))
    ev("kernel", kept=kept, retired=retired,
       retiring=[label for k, label in RETIRE if k not in on],
       keeping=[label for k, label in KEEP if k in on])


class Tracker:
    def __init__(self, info, journal, out):
        self.pkgs = {k: v for k, v in info.items() if not v.get("virtual")}
        self.total = sum(WEIGHT.get(k, 1) for k in self.pkgs)
        self.state = {}
        self.done = set(journal.get("done", []))
        # Buildroot's own stamps say what finished before an interruption.
        for k, v in self.pkgs.items():
            bd = os.path.join(out, v.get("build_dir") or "")
            for st in (".stamp_target_installed", ".stamp_host_installed", ".stamp_images_installed"):
                if os.path.exists(os.path.join(bd, st)):
                    self.done.add(k)
            if not v.get("install_target") and os.path.exists(os.path.join(bd, ".stamp_staging_installed")):
                self.done.add(k)
        self.active = set()
        self.kernel_told = False

    def pct(self):
        w = sum(WEIGHT.get(k, 1) for k in self.done if k in self.pkgs)
        part = sum(WEIGHT.get(k, 1) * 0.5 for k in self.active if k in self.pkgs)
        return min(99.0, 100.0 * (w + part) / max(1, self.total))

    def line(self, pkg, step):
        if pkg not in self.pkgs:
            return
        self.state[pkg] = step
        final = step.startswith("Installing to target") or step.startswith("Installing to host") or \
            step.startswith("Installing to images")
        if step.startswith("Extracting") or step.startswith("Building") or step.startswith("Configuring"):
            self.active.add(pkg)
        if final or (step.startswith("Installing to staging") and not self.pkgs[pkg].get("install_target")):
            self.active.discard(pkg)
            self.done.add(pkg)
        ph = phase_of(pkg)
        extra = {}
        if pkg in PROTO_LABEL and final:
            extra["protocol"] = PROTO_LABEL[pkg]
        ev("pkg", name=pkg, version=self.pkgs[pkg].get("version", ""), step=step, phase=ph,
           active=sorted(self.active), done=len(self.done), total=len(self.pkgs), pct=round(self.pct(), 1), **extra)


def cpu_sampler(stop):
    def read():
        out = []
        with open("/proc/stat") as f:
            for l in f:
                if re.match(r"cpu\d", l):
                    v = [int(x) for x in l.split()[1:]]
                    out.append((sum(v), v[3] + v[4]))
        return out
    prev = read()
    while not stop.is_set():
        time.sleep(1)
        cur = read()
        cores = []
        for (t0, i0), (t1, i1) in zip(prev, cur):
            dt = t1 - t0
            cores.append(round(100.0 * (1 - (i1 - i0) / dt), 1) if dt else 0.0)
        prev = cur
        ev("cpu", cores=cores)


def cmd_build(a):
    started = time.time()
    os.makedirs(WS, exist_ok=True)
    jpath = os.path.join(WS, "journal-%s-%s.json" % (a.arch, a.variant))
    journal = json.load(open(jpath)) if os.path.exists(jpath) else {}
    if journal.get("pct"):
        ev("resume", phase=journal.get("phase"), pct=journal.get("pct"), done=len(journal.get("done", [])))

    def save(**kw):
        journal.update(kw)
        tmp = jpath + ".tmp"
        with open(tmp, "w") as f:
            json.dump(journal, f)
        os.replace(tmp, jpath)

    ev("phase", phase="sources", state="start", label="Gathering sources")
    br_tar = os.path.join(DL, BUILDROOT + ".tar.xz")
    if not fetch(BUILDROOT_URL, br_tar, BUILDROOT + ".tar.xz", BUILDROOT_SHA256):
        fail("could not download Buildroot")
    br = os.path.join(WS, BUILDROOT)
    if not os.path.exists(os.path.join(br, ".ftk-extracted")):
        shutil.rmtree(br, ignore_errors=True)
        subprocess.run(["tar", "-xJf", br_tar, "-C", WS], check=True)
        open(os.path.join(br, ".ftk-extracted"), "w").close()

    ext = os.path.join(WS, "external")
    subprocess.run(["rsync", "-a", "--delete", a.src.rstrip("/") + "/", ext + "/"], check=True)
    # Files copied from Windows lose their execute bits.
    for root, _, files in os.walk(ext):
        for f in files:
            if f.endswith(".sh") or "/init.d" in root:
                os.chmod(os.path.join(root, f), 0o755)
    agent = os.path.join(WS, "ftk-agent-" + a.arch)
    shutil.copy(a.agent, agent)
    os.chmod(agent, 0o755)

    out = os.path.join(WS, "out", "%s-%s" % (a.arch, a.variant))
    os.environ["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    mk = ["make", "-C", br, "O=" + out, "BR2_EXTERNAL=" + ext]
    defcfg = os.path.join(ext, "configs", "ftkos_%s_defconfig" % a.arch)
    sig = hashlib.sha256((open(defcfg).read() + a.opt).encode()).hexdigest()
    if journal.get("config_sig") != sig or not os.path.exists(os.path.join(out, ".config")):
        subprocess.run(mk + ["ftkos_%s_defconfig" % a.arch], check=True, stdout=subprocess.DEVNULL)
        if a.opt:
            with open(os.path.join(out, ".config"), "a") as f:
                f.write('BR2_TARGET_OPTIMIZATION="%s"\n' % a.opt.replace('"', ""))
            subprocess.run(mk + ["olddefconfig"], check=True, stdout=subprocess.DEVNULL)
        save(config_sig=sig)
    info = json.loads(subprocess.run(mk + ["-s", "show-info"], check=True, stdout=subprocess.PIPE, text=True).stdout)
    prefetch_sources(info)
    ev("phase", phase="sources", state="done", label="Sources gathered")
    save(phase="build")

    tr = Tracker(info, journal, out)
    if tr.done:
        ev("resume", phase="build", pct=round(tr.pct(), 1), done=len(tr.done))
    # Buildroot refuses a PATH with spaces (Windows folders) and must not see Windows tools.
    env = dict(os.environ, BR2_DL_DIR=DL, FTK_AGENT_BIN=agent, FTK_BUILD_ID=a.build_id,
               PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
    env.pop("LD_LIBRARY_PATH", None)
    stop = threading.Event()
    threading.Thread(target=cpu_sampler, args=(stop,), daemon=True).start()
    ev("phase", phase="build", state="start", label="Compiling", jobs=a.jobs)
    p = subprocess.Popen(mk + ["-j%d" % a.jobs], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         text=True, errors="replace", bufsize=1)
    tail = []
    last_save = 0
    for line in p.stdout:
        line = ANSI.sub("", line.rstrip("\n"))
        tail = (tail + [line])[-200:]
        m = LINE.match(line)
        if m:
            pkg, ver, step = m.groups()
            if pkg in ("Finalizing", "Sanitizing") or line.startswith(">>>   Finalizing"):
                ev("phase", phase="seal", state="start", label="Stripping and sealing")
            tr.line(pkg, step)
            if pkg == "linux" and step.startswith("Building") and not tr.kernel_told:
                tr.kernel_told = True
                kernel_report(os.path.join(out, "build", "linux-" + ver, ".config"))
            if time.time() - last_save > 2:
                save(done=sorted(tr.done), pct=round(tr.pct(), 1))
                last_save = time.time()
        elif "Finalizing target directory" in line:
            ev("phase", phase="seal", state="start", label="Stripping and sealing")
        elif "Generating root filesystem image rootfs.erofs" in line:
            ev("phase", phase="pack", state="start", label="Packing the image")
        else:
            log(line)
    rc = p.wait()
    stop.set()
    save(done=sorted(tr.done), pct=round(tr.pct(), 1))
    if rc != 0:
        ev("error", msg="the build stopped with an error", tail=tail[-40:])
        sys.exit(rc)

    images = os.path.join(out, "images")
    kname = "bzImage" if a.arch == "x86_64" else "Image"
    os.makedirs(a.out, exist_ok=True)
    outputs = {}
    for src, dst in ((kname, "kernel"), ("rootfs.erofs", "rootfs.erofs")):
        tmp = os.path.join(a.out, dst + ".tmp")
        shutil.copy(os.path.join(images, src), tmp)
        os.replace(tmp, os.path.join(a.out, dst))
        outputs[dst] = {"bytes": os.path.getsize(os.path.join(a.out, dst)), "sha256": sha_file(os.path.join(a.out, dst))}
    pkgs = {k: v.get("version", "") for k, v in info.items() if not v.get("virtual") and v.get("type") == "target"}
    build_info = {
        "arch": a.arch, "variant": a.variant, "opt": a.opt, "build_id": a.build_id,
        "buildroot": BUILDROOT, "kernel_version": info.get("linux", {}).get("version"),
        "packages": pkgs, "outputs": outputs, "seconds": round(time.time() - started),
        "jobs": a.jobs, "host_cpus": os.cpu_count(),
    }
    with open(os.path.join(a.out, "build-info.json"), "w") as f:
        json.dump(build_info, f, indent=1)
    save(pct=100.0, phase="done")
    ev("done", outputs=outputs, seconds=build_info["seconds"])


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("setup")
    b = sub.add_parser("build")
    b.add_argument("--arch", choices=["x86_64", "aarch64"], required=True)
    b.add_argument("--variant", default="generic")
    b.add_argument("--opt", default="", help="extra target CFLAGS for a tuned build")
    b.add_argument("--jobs", type=int, default=os.cpu_count() or 4)
    b.add_argument("--src", required=True, help="the FTKOS Buildroot external tree")
    b.add_argument("--agent", required=True, help="prebuilt ftk-agent for this arch")
    b.add_argument("--out", required=True, help="where to put kernel, rootfs.erofs, build-info.json")
    b.add_argument("--build-id", default="dev")
    a = ap.parse_args()
    {"setup": cmd_setup, "build": cmd_build}[a.cmd](a)


if __name__ == "__main__":
    main()
