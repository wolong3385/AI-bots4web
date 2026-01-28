import sys
import os
import json
import warnings

# 这个 warning 不影响运行；如果你想彻底消除，看后面的 pip 方案
if sys.platform == "darwin":
    try:
        from urllib3.exceptions import NotOpenSSLWarning
        warnings.filterwarnings("ignore", category=NotOpenSSLWarning)
    except Exception:
        pass

import requests


def load_payloads(filename: str) -> dict:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    path = filename if os.path.isabs(filename) else os.path.join(base_dir, filename)
    print(f"[*] __file__      = {__file__}")
    print(f"[*] base_dir     = {base_dir}")
    print(f"[*] cwd          = {os.getcwd()}")
    print(f"[*] payload_path = {path}")

    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def looks_like_error(text: str) -> bool:
    sigs = [
        "SQLITE_ERROR",
        "SQLiteError",
        "SQL syntax",
        "unrecognized token",
        "SequelizeDatabaseError",
        "TypeError",
        "ER_PARSE_ERROR",
    ]
    t = (text or "").lower()
    return any(s.lower() in t for s in sigs)


def main():
    target = "http://localhost:3000"
    if len(sys.argv) > 1:
        target = sys.argv[1]
    target = target.rstrip("/")

    print("=" * 60)
    print(f"  Scan start: {target}")
    print("=" * 60)

    payloads = load_payloads("payloads.json")
    closures = payloads.get("closures", ["'"])
    debug_snippet = bool(payloads.get("debug_snippet", True))

    # 1) 连通性检查
    try:
        r = requests.get(target, timeout=10)
        print(f"[*] GET / => HTTP {r.status_code}")
    except Exception as e:
        print(f"[x] Target unreachable: {e}")
        return

    # 2) Search API 探测
    api = f"{target}/rest/products/search"
    print(f"[*] Probing: {api}")

    for c in closures:
        q = f"apple{c}"
        try:
            res = requests.get(api, params={"q": q}, timeout=10)
        except Exception as e:
            print(f"[!] closure={repr(c)} request failed: {e}")
            continue

        err = (res.status_code >= 500) or looks_like_error(res.text)
        print(f"[*] closure={repr(c)} -> HTTP {res.status_code}, looks_err={err}")

        if debug_snippet:
            snippet = (res.text or "")[:200].replace("\n", "\\n")
            print(f"    snippet={snippet}")

    print("=" * 60)
    print("  Done.")


if __name__ == "__main__":
    main()
