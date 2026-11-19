#!/usr/bin/env python3
"""Pinned Garble release build; Authenticode is mandatory unless --unsigned is explicit."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import zipfile
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
GARBLE_VERSION = "v0.18.0"
GO_VERSION = "go1.27."
CONTROLFLOW = "GARBLE_EXPERIMENTAL_CONTROLFLOW"
ANNOTATED = "cmd/collector/license_windows.go"
SYMBOL = "authorizeCaptureWithCard"
EXES = ("capture.exe", "CS2雷达.exe")


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--go", default="go")
    p.add_argument("--garble", default="garble")
    p.add_argument("--signtool", default="signtool")
    p.add_argument("--out", type=Path, required=True, help="fresh output directory")
    p.add_argument("--config-dir", type=Path, default=ROOT / "dist", help="directory containing public capture.json and license.json")
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--unsigned", action="store_true", help="explicit test build, NOT signed")
    mode.add_argument("--certificate-thumbprint", help="SHA-1 thumbprint in Windows My store")
    p.add_argument("--machine-store", action="store_true", help="use LocalMachine instead of CurrentUser")
    p.add_argument("--timestamp-url", default="http://timestamp.digicert.com")
    p.add_argument("--plan", action="store_true", help="print commands without invoking tools")
    return p


def plan(a):
    out = a.out.resolve()
    thumb = re.sub(r"\s", "", a.certificate_thumbprint or "").upper()
    if not a.unsigned and not re.fullmatch(r"[A-F0-9]{40}", thumb):
        raise ValueError("certificate thumbprint must contain 40 hexadecimal characters")
    if not a.unsigned and not re.match(r"^https?://[^\s]+$", a.timestamp_url):
        raise ValueError("an HTTP(S) RFC3161 timestamp URL is required")
    if a.unsigned and a.machine_store:
        raise ValueError("--machine-store requires a signing certificate")
    commands = []
    for name in EXES:
        ldflags = "-s -w"
        if name != "capture.exe":
            ldflags += " -H=windowsgui -X main.defaultGUIMode=true"
        commands.append([a.garble, "-literals", "-tiny", "-seed=random", "build",
                         "-mod=vendor", "-trimpath", "-ldflags=" + ldflags,
                         "-o", str(out / name), "./cmd/collector"])
    if not a.unsigned:
        for name in EXES:
            sign = [a.signtool, "sign", "/v", "/s", "My", "/sha1", thumb,
                    "/fd", "SHA256", "/tr", a.timestamp_url, "/td", "SHA256"]
            if a.machine_store:
                sign.append("/sm")
            commands.append(sign + [str(out / name)])
            commands.append([a.signtool, "verify", "/pa", "/all", "/v", "/tw", str(out / name)])
    return {"environment": {CONTROLFLOW: "1", "GOGARBLE": "*", "CGO_ENABLED": "0",
                             "GOOS": "windows", "GOARCH": "amd64", "GOTOOLCHAIN": "local"},
            "annotated_function": SYMBOL, "signing_requested": not a.unsigned,
            "commands": commands}


def resolve_tool(name):
    p = shutil.which(name)
    if not p:
        raise ValueError("tool not found: " + name)
    return str(Path(p).resolve())


def public_configuration_files(directory):
    """Offline syntax checks only. Copy public config/certificates, never device state or cards."""
    directory = Path(directory).resolve()
    files = {}
    configs = {}
    for name in ("capture.json", "license.json"):
        raw = (directory / name).read_bytes()
        if len(raw) > 16384:
            raise ValueError("public configuration exceeds size limit: " + name)
        obj = json.loads(raw.decode("utf-8"))
        if not isinstance(obj, dict):
            raise ValueError("public configuration must be an object: " + name)
        configs[name] = obj
        files[name] = raw
    capture, license = configs["capture.json"], configs["license.json"]
    allowed_capture = {"uplink", "proc", "ca", "session", "token", "listen", "insecure",
                       "pid", "duration", "no_keys", "no_filter", "scan_budget"}
    if set(capture) - allowed_capture or set(license) - {"endpoint", "app_key", "app_id", "ca_file"}:
        raise ValueError("unexpected public configuration fields; do not package secrets")
    def valid_url(raw, ingest=False):
        if not isinstance(raw, str) or not raw or raw.strip() != raw or any(c in raw for c in "\\\r\n\t?#"):
            return False
        try:
            u = urlsplit(raw)
            return (u.scheme == "https" and bool(u.hostname) and u.username is None and u.password is None
                    and not u.netloc.endswith(":") and (u.port is None or 1 <= u.port <= 65535)
                    and (u.path == "/api/v1/ingest" if ingest else bool(u.path)) and "%" not in u.path)
        except ValueError:
            return False
    if not valid_url(capture.get("uplink"), ingest=True):
        raise ValueError("capture.json requires a credential-free HTTPS /api/v1/ingest uplink")
    if (capture.get("token") or capture.get("listen") or capture.get("insecure")
            or capture.get("no_filter") or capture.get("session", "default") != "default"):
        raise ValueError("legacy or insecure capture configuration is forbidden")
    if (not valid_url(license.get("endpoint")) or not isinstance(license.get("app_key"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", license["app_key"])
            or type(license.get("app_id")) is not int or license["app_id"] <= 0):
        raise ValueError("license.json requires valid public endpoint/app_key/app_id")
    for obj, key in ((capture, "ca"), (license, "ca_file")):
        name = obj.get(key)
        if not name:
            continue
        if not isinstance(name, str) or Path(name).is_absolute():
            raise ValueError("CA paths must be portable paths within config-dir")
        path = (directory / name).resolve()
        if not path.is_relative_to(directory):
            raise ValueError("CA path escapes config-dir")
        raw = path.read_bytes()
        if len(raw) > 262144 or b"PRIVATE KEY" in raw or b"-----BEGIN CERTIFICATE-----" not in raw:
            raise ValueError("only public PEM CA certificates may be distributed")
        relative = path.relative_to(directory).as_posix()
        if relative in files:
            raise ValueError("CA path conflicts with configuration")
        files[relative] = raw
    return files


def run(command, env, log):
    r = subprocess.run(command, cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # Keep full build output private: Garble may emit a per-build random seed.
    record = {"argv": command, "exit_status": r.returncode,
              "stdout": r.stdout.decode("utf-8", "replace"),
              "stderr": r.stderr.decode("utf-8", "replace")}
    with log.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
    if r.returncode:
        raise RuntimeError("tool failed (exit %d); see private build log: %s" % (r.returncode, log))
    return record["stdout"] + record["stderr"]


def build(a):
    p = plan(a)
    if a.plan:
        print(json.dumps(p, ensure_ascii=False, indent=2))
        return 0
    if a.out.exists():
        raise ValueError("fresh output directory required: " + str(a.out))
    public_files = public_configuration_files(a.config_dir)
    marker = "//garble:controlflow block_splits=2 junk_jumps=1 flatten_passes=1"
    text = (ROOT / ANNOTATED).read_text(encoding="utf-8")
    if marker + "\nfunc " + SYMBOL + "(" not in text:
        raise ValueError("expected control-flow annotation is absent")
    a.go = resolve_tool(a.go)
    a.garble = resolve_tool(a.garble)
    if not a.unsigned:
        if os.name != "nt":
            raise ValueError("Authenticode signing must run on Windows")
        a.signtool = resolve_tool(a.signtool)
    a.out = a.out.resolve()
    a.out.mkdir(parents=True, exist_ok=False)
    env = os.environ.copy()
    env.update(p["environment"])
    env["PATH"] = str(Path(a.go).parent) + os.pathsep + env.get("PATH", "")
    # Do not modify global Go environment or tool caches.
    env["GOENV"] = "off"
    env["GARBLE_CACHE"] = str(a.out / ".private-garble-cache")
    log = a.out / "BUILD-PRIVATE.jsonl"
    go_version = run([a.go, "version"], env, log).strip()
    garble_version = run([a.garble, "version"], env, log).strip()
    if GO_VERSION not in go_version or GARBLE_VERSION not in garble_version:
        raise ValueError("requires Go 1.27.x and Garble " + GARBLE_VERSION)
    p = plan(a)
    for command in p["commands"]:
        run(command, env, log)
    for name, raw in public_files.items():
        path = a.out / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    # Only hash and package after every build, sign and verification succeeded.
    if (ROOT / "dist/maps").is_dir():
        shutil.copytree(ROOT / "dist/maps", a.out / "maps")
    warning = ("混淆构建：-literals -tiny；授权入口已启用实验性控制流。\n"
               "签名状态：" + ("未签名，仅供测试。" if a.unsigned else "SignTool 验签通过。") + "\n"
               "已附带经离线格式校验的公开配置；不含卡密、设备私钥或 api_secret。\n"
               "混淆不等于加密，数字签名不等于防破解或免封号。\n")
    (a.out / "保护构建说明.txt").write_text(warning, encoding="utf-8-sig")
    names = [*EXES, "保护构建说明.txt", *sorted(public_files)]
    if (a.out / "maps").exists():
        names.extend(str(f.relative_to(a.out)).replace("\\", "/")
                     for f in sorted((a.out / "maps").rglob("*")) if f.is_file())
    manifest = {"schema": 1, "garble": GARBLE_VERSION, "go": go_version,
                "literals": True, "tiny": True, "experimental_controlflow": [SYMBOL],
                "authenticode_verified": not a.unsigned,
                "public_configuration_checked_offline": True,
                "files": {n: hashlib.sha256((a.out / n).read_bytes()).hexdigest() for n in names}}
    (a.out / "BUILD-INFO.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    names.append("BUILD-INFO.json")
    bundle = a.out / ("protected-UNSIGNED.zip" if a.unsigned else "protected-SIGNED.zip")
    with zipfile.ZipFile(bundle, "x", zipfile.ZIP_DEFLATED) as z:
        for name in names:
            z.write(a.out / name, name)
    print(json.dumps({"bundle": str(bundle), "sha256": hashlib.sha256(bundle.read_bytes()).hexdigest(),
                      "authenticode_verified": not a.unsigned}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(build(parser().parse_args()))
    except (ValueError, RuntimeError, OSError) as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)
