"""Exercise the OAuth code flow across two independent server processes.

Instance A issues the authorization code, instance B redeems it — that is the
Cloud Run multi-instance case the old process-level dict could not survive.
"""
import base64, hashlib, os, pathlib, secrets, subprocess, sys, time, urllib.parse
import urllib.request, urllib.error

REPO  = pathlib.Path(__file__).resolve().parent
TOKEN = "test-auth-token"
A, B = 8201, 8202


def start(port):
    env = dict(os.environ, AUTH_TOKEN=TOKEN, PORT=str(port), GITHUB_REPO="x/y", GITHUB_TOKEN="z")
    p = subprocess.Popen([sys.executable, "server.py"], env=env, cwd=REPO,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(80):
        try:
            urllib.request.urlopen(f"http://localhost:{port}/health", timeout=1).read()
            return p
        except Exception:
            time.sleep(0.25)
    p.kill()
    raise SystemExit(f"server on {port} never came up")


def req(url, data=None, headers=None, method=None):
    body = urllib.parse.urlencode(data).encode() if data else None
    r = urllib.request.Request(url, data=body, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(r) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def authorize(port, redirect_uri, challenge, password=TOKEN):
    """POST the login form, return the 302 Location (or the error status)."""
    opener = urllib.request.build_opener(NoRedirect)
    body = urllib.parse.urlencode({
        "password": password, "client_id": "c1", "redirect_uri": redirect_uri,
        "state": "st", "code_challenge": challenge, "code_challenge_method": "S256",
    }).encode()
    r = urllib.request.Request(f"http://localhost:{port}/oauth/authorize", data=body, method="POST")
    try:
        with opener.open(r) as resp:
            return resp.status, resp.headers.get("Location", "")
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Location", "")


def token(port, code, verifier, redirect_uri):
    return req(f"http://localhost:{port}/oauth/token", data={
        "grant_type": "authorization_code", "code": code,
        "code_verifier": verifier, "redirect_uri": redirect_uri,
    })


results = []


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"{'PASS' if ok else 'FAIL'}  {name}{'  — ' + detail if detail and not ok else ''}")


pa, pb = start(A), start(B)
try:
    RU = "https://client.example/cb"
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")

    # 1. THE FIX: authorize on instance A, redeem on instance B.
    status, loc = authorize(A, RU, challenge)
    code = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query).get("code", [""])[0]
    check("authorize on A returns a code", status == 302 and bool(code), f"status={status}")

    st, body = token(B, code, verifier, RU)
    check("code from A redeems on B (cross-instance)", st == 200 and "access_token" in body,
          f"status={st} body={body[:120]}")

    access = ""
    if st == 200:
        import json
        access = json.loads(body)["access_token"]

    # 2. That access token works on either instance.
    for port, label in ((A, "A"), (B, "B")):
        st, _ = req(f"http://localhost:{port}/mcp?token={urllib.parse.quote(access)}")
        check(f"access token accepted on {label}", st != 401, f"status={st}")

    # 3. Replay of an already-redeemed code is refused on that instance.
    st, _ = token(B, code, verifier, RU)
    check("replay on same instance refused", st == 400, f"status={st}")

    # 4. Domain separation: an auth code must not work as a bearer token.
    status, loc = authorize(A, RU, challenge)
    code2 = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query).get("code", [""])[0]
    st, _ = req(f"http://localhost:{A}/mcp?token={urllib.parse.quote(code2)}")
    check("auth code rejected as bearer token", st == 401, f"status={st}")

    # 5. Wrong PKCE verifier is refused.
    st, _ = token(A, code2, secrets.token_urlsafe(48), RU)
    check("wrong code_verifier refused", st == 400, f"status={st}")

    # 6. redirect_uri mismatch is refused.
    status, loc = authorize(A, RU, challenge)
    code3 = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query).get("code", [""])[0]
    st, _ = token(A, code3, verifier, "https://evil.example/cb")
    check("redirect_uri mismatch refused", st == 400, f"status={st}")

    # 7. Wrong login password gets no code.
    status, loc = authorize(A, RU, challenge, password="wrong")
    check("bad password issues no code", "code=" not in loc, f"loc={loc[:80]}")

    # 8. Unauthenticated request still refused.
    st, _ = req(f"http://localhost:{A}/mcp")
    check("no token still 401", st == 401, f"status={st}")
finally:
    pa.kill(); pb.kill()

failed = [n for n, ok, _ in results if not ok]
print(f"\n{len(results) - len(failed)}/{len(results)} passed")
sys.exit(1 if failed else 0)
