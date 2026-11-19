#!/usr/bin/env python3
"""Offline, standard-library-only template rendering. Never installs or starts services."""
import argparse
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent
FIELDS = {"schema", "public_origin", "app_id", "guyi_project", "php_binary", "security_epoch"}

def reject_duplicates(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError("duplicate configuration field")
        d[k] = v
    return d

def load_config(path):
    raw = Path(path).read_bytes()
    if len(raw) > 8192:
        raise ValueError("configuration too large")
    c = json.loads(raw, object_pairs_hook=reject_duplicates)
    if not isinstance(c, dict) or set(c) != FIELDS or type(c["schema"]) is not int or type(c["security_epoch"]) is not int or c["schema"] != 1 or c["security_epoch"] != 1:
        raise ValueError("unsupported configuration schema/fields/epoch")
    if type(c["app_id"]) is not int or not 1 <= c["app_id"] <= 2147483647:
        raise ValueError("app_id must be a configured positive integer")
    origin = c["public_origin"]
    if not isinstance(origin, str) or not re.fullmatch(r"https://[A-Za-z0-9.:-]+", origin):
        raise ValueError("exact HTTPS origin required; credentials/path/query forbidden")
    u = urlsplit(origin)
    if u.scheme != "https" or u.username or u.password or not u.hostname or u.port not in (None,443):
        raise ValueError("public HTTPS port 443 required")
    # This deployment is intentionally an IPv4 IP-HTTPS endpoint, not a DNS fallback.
    ip = ipaddress.ip_address(u.hostname)
    if ip.version != 4 or not ip.is_global or origin != "https://" + str(ip):
        raise ValueError("canonical public IPv4 HTTPS origin required")
    for key in ("guyi_project", "php_binary"):
        p = c[key]
        if not isinstance(p,str) or not re.fullmatch(r"/[A-Za-z0-9_./-]+",p) or ".." in p.split("/") or str(PurePosixPath(p)) != p or p == "/":
            raise ValueError("safe canonical absolute Linux backend path required")
    return c

def render(config, output):
    c = load_config(config)
    substitutions = {"ORIGIN":c["public_origin"], "HOST":urlsplit(c["public_origin"]).netloc, "APP_ID":str(c["app_id"]), "GUYI_PROJECT":c["guyi_project"], "PHP_BINARY":c["php_binary"]}
    files = {}
    for name in ("gamesense-radar.service", "gamesense-radar-locations.conf", "gamesense-radar-upstream.conf", "gamesense-avatar-locations.conf", "rollback-release.sh"):
        text = (ROOT / "templates" / (name+".in")).read_text(encoding="utf-8")
        for key,value in substitutions.items():
            text = text.replace("@@"+key+"@@", value)
        if "@@" in text:
            raise ValueError("unresolved template field")
        files[name] = text.encode("utf-8")
    policy = {"schema":1,"security_epoch":1,"public_origin":c["public_origin"],"app_id":c["app_id"]}
    files["policy.json"] = (json.dumps(policy,indent=2)+"\n").encode()
    files["approved-releases.json"] = b'{"schema":1,"manifest_sha256":[]}\n'
    files["release-trust.json"] = b'{"schema":1,"algorithm":"Ed25519","public_key_sha256":null}\n'
    files["release_check.py"] = (ROOT/"release_check.py").read_bytes()
    files["rollout.py"] = (ROOT/"rollout.py").read_bytes()
    files["approved-rollouts.json"] = b'{"schema":1,"plan_sha256":[]}\n'
    files["RENDERED-NOT-INSTALLED.txt"] = b"OFFLINE OUTPUT ONLY. No release is approved or signing key trusted. No service, database, certificate or firewall was changed.\n"
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise ValueError("fresh output directory required")
    output.mkdir(mode=0o700 if os.name=='posix' else 0o755)
    for name,raw in files.items():
        with (output/name).open("xb") as f:
            f.write(raw)
        (output/name).chmod(0o700 if name.endswith((".sh",".py")) else 0o600)
    return sorted(files)

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--config",required=True)
    p.add_argument("--out",required=True)
    a = p.parse_args()
    try:
        files = render(a.config,a.out)
    except (OSError, ValueError, TypeError, UnicodeError):
        print("RENDER_DENIED: invalid configuration or non-fresh output; no activation attempted",file=sys.stderr)
        return 2
    print(json.dumps({"rendered":files,"installed":False,"approved_releases":0}))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
