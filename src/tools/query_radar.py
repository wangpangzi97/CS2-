import json, sys, urllib.request

BASE = "http://127.0.0.1:8080"


def get(path):
    op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with op.open(BASE + path, timeout=10) as r:
        return json.load(r)


def main():
    sess = sys.argv[1] if len(sys.argv) > 1 else "demo"

    print("=== 加解密方案搜索（Top-6，含落选方案）===")
    d = get("/api/v1/probe?session=" + sess)
    print("方向=%s  帧数=%d  有私钥=%s  有公钥=%s" % (
        d["direction"], d["frames"], d["has_key"], d["has_pub"]))
    for i, r in enumerate(d["results"][:6]):
        print("  #%d %-30s %-13s %-16s off=%d salt=%-5s  OK帧=%2d/%d  消息=%3d  成立=%s" % (
            i + 1, r["KDF"], r["Cipher"], r["Nonce"], r["Offset"], r["UseSaltPub"],
            r["OKFrames"], r["Frames"], r["Messages"], r["OK"]))

    print()
    print("=== 雷达画面 ===")
    s = get("/api/v1/radar?session=" + sess)
    print("会话=%s" % s["session"])
    print("选中方案=%s" % (s["scheme"] or "(尚未命中)"))
    print("已解消息=%d  可解帧=%d  目标数=%d" % (
        s["decoded_msgs"], s["encrypted_frames"], len(s["players"])))
    for p in s["players"]:
        print("  #%d  x=%9.2f  y=%9.2f  z=%6.2f  来源=%s" % (
            p["id"], p["pos"]["x"], p["pos"]["y"], p["pos"]["z"], p["source"]))


main()
