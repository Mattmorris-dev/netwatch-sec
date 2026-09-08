"""Enterprise auth wiring in the free app: MFA login legs, account lockout,
API-key auth, session epochs/idle, /logout, OIDC routes and the CSP header.
All Pro substance is mocked — these tests prove the free app's wiring."""
import json
import time
from unittest.mock import MagicMock

import pytest

import netwatch


ORIGIN = None


@pytest.fixture(autouse=True)
def _fresh_limiter():
    netwatch._auth_attempts.clear()
    yield
    netwatch._auth_attempts.clear()


def _origin():
    return {"Origin": f"http://127.0.0.1:{netwatch.WEB_PORT}"}


@pytest.fixture
def client():
    netwatch.web_app.config["TESTING"] = True
    with netwatch.web_app.test_client() as c:
        yield c


def _ent_mod(**kw):
    """A stand-in netwatch_pro.enterprise_auth."""
    mod = MagicMock()
    mod.lockout_state.return_value = {"locked": False, "retry_after": 0.0}
    mod.mfa_required.return_value = False
    mod.session_epoch.return_value = 0
    mod.verify_totp.return_value = True
    mod.verify_api_key.return_value = None
    for k, v in kw.items():
        setattr(mod, k, v)
    return mod


def _wire(monkeypatch, ent=None, webauth=None, sso=None, tier="enterprise"):
    ranks = {"free": 0, "pro": 1, "team": 2, "enterprise": 3}
    monkeypatch.setattr(netwatch, "tier_at_least",
                        lambda t: ranks.get(tier, 0) >= ranks.get(t, 0))
    mods = {"enterprise_auth": ent, "webauth": webauth, "sso_oidc": sso}
    monkeypatch.setattr(netwatch, "_pro_sub", lambda n: mods.get(n))
    return mods


def _webauth(role="operator"):
    wa = MagicMock()
    wa.verify.return_value = role
    wa.current_role.return_value = role
    return wa


# ── the unchanged paths ─────────────────────────────────────────────────────

def test_token_login_still_works_without_enterprise(client, monkeypatch):
    _wire(monkeypatch, tier="free")
    r = client.post("/auth", json={"token": netwatch.WEB_TOKEN}, headers=_origin())
    assert r.status_code == 200 and r.get_json()["ok"] is True


def test_password_login_without_mfa_mints_a_session(client, monkeypatch):
    ent = _ent_mod()
    _wire(monkeypatch, ent=ent, webauth=_webauth("operator"))
    r = client.post("/auth", json={"user": "alice", "pass": "pw"}, headers=_origin())
    assert r.status_code == 200 and r.get_json()["role"] == "operator"
    assert client.get_cookie("nw_sess") is not None
    ent.record_success.assert_called_once_with("alice")


# ── MFA ─────────────────────────────────────────────────────────────────────

def test_password_alone_is_not_a_session_when_mfa_is_on(client, monkeypatch):
    ent = _ent_mod(mfa_required=MagicMock(return_value=True))
    _wire(monkeypatch, ent=ent, webauth=_webauth("admin"))
    r = client.post("/auth", json={"user": "alice", "pass": "pw"}, headers=_origin())
    body = r.get_json()
    assert r.status_code == 200 and body["mfa_required"] is True and body["challenge"]
    assert client.get_cookie("nw_sess") is None        # no session yet


def test_mfa_challenge_completes_the_login(client, monkeypatch):
    ent = _ent_mod(mfa_required=MagicMock(return_value=True))
    _wire(monkeypatch, ent=ent, webauth=_webauth("operator"))
    challenge = client.post("/auth", json={"user": "alice", "pass": "pw"},
                            headers=_origin()).get_json()["challenge"]
    r = client.post("/auth", json={"challenge": challenge, "code": "123456"},
                    headers=_origin())
    assert r.status_code == 200 and r.get_json()["role"] == "operator"
    ent.verify_totp.assert_called_once_with("alice", "123456")
    assert client.get_cookie("nw_sess") is not None


def test_wrong_mfa_code_is_401_and_counts_a_failure(client, monkeypatch):
    ent = _ent_mod(mfa_required=MagicMock(return_value=True),
                   verify_totp=MagicMock(return_value=False))
    _wire(monkeypatch, ent=ent, webauth=_webauth("operator"))
    challenge = client.post("/auth", json={"user": "alice", "pass": "pw"},
                            headers=_origin()).get_json()["challenge"]
    r = client.post("/auth", json={"challenge": challenge, "code": "000000"},
                    headers=_origin())
    assert r.status_code == 401
    ent.record_failure.assert_called_with("alice")
    assert client.get_cookie("nw_sess") is None


def test_forged_challenge_rejected(client, monkeypatch):
    ent = _ent_mod()
    _wire(monkeypatch, ent=ent, webauth=_webauth())
    r = client.post("/auth", json={"challenge": "not-a-real-blob", "code": "1"},
                    headers=_origin())
    assert r.status_code == 401
    ent.verify_totp.assert_not_called()


def test_challenge_from_another_purpose_rejected(client, monkeypatch):
    """A session cookie must not be reusable as an MFA challenge."""
    ent = _ent_mod()
    _wire(monkeypatch, ent=ent, webauth=_webauth())
    blob = netwatch._mint_session("alice", "admin")
    r = client.post("/auth", json={"challenge": blob, "code": "123456"},
                    headers=_origin())
    assert r.status_code == 401
    ent.verify_totp.assert_not_called()


def test_expired_challenge_rejected(client, monkeypatch):
    ent = _ent_mod()
    _wire(monkeypatch, ent=ent, webauth=_webauth())
    monkeypatch.setattr(netwatch, "_MFA_CHALLENGE_TTL", -1)
    blob = netwatch._mint_mfa_challenge("alice", "admin")
    r = client.post("/auth", json={"challenge": blob, "code": "123456"},
                    headers=_origin())
    assert r.status_code == 401


def test_role_is_reread_between_the_two_legs(client, monkeypatch):
    """A demotion (or removal) between password and code must win."""
    wa = _webauth("admin")
    ent = _ent_mod(mfa_required=MagicMock(return_value=True))
    _wire(monkeypatch, ent=ent, webauth=wa)
    challenge = client.post("/auth", json={"user": "alice", "pass": "pw"},
                            headers=_origin()).get_json()["challenge"]
    wa.current_role.return_value = "viewer"
    r = client.post("/auth", json={"challenge": challenge, "code": "123456"},
                    headers=_origin())
    assert r.get_json()["role"] == "viewer"


def test_removed_user_cannot_finish_mfa(client, monkeypatch):
    wa = _webauth("admin")
    ent = _ent_mod(mfa_required=MagicMock(return_value=True))
    _wire(monkeypatch, ent=ent, webauth=wa)
    challenge = client.post("/auth", json={"user": "alice", "pass": "pw"},
                            headers=_origin()).get_json()["challenge"]
    wa.current_role.return_value = None
    r = client.post("/auth", json={"challenge": challenge, "code": "123456"},
                    headers=_origin())
    assert r.status_code == 401


def test_mfa_required_fails_closed(client, monkeypatch):
    """An unreadable MFA store must demand the second factor, not skip it."""
    ent = _ent_mod(mfa_required=MagicMock(side_effect=OSError("boom")))
    _wire(monkeypatch, ent=ent, webauth=_webauth())
    r = client.post("/auth", json={"user": "alice", "pass": "pw"}, headers=_origin())
    assert r.get_json()["mfa_required"] is True


# ── lockout ─────────────────────────────────────────────────────────────────

def test_locked_account_gets_429_with_retry_after(client, monkeypatch):
    ent = _ent_mod(lockout_state=MagicMock(
        return_value={"locked": True, "retry_after": 120}))
    _wire(monkeypatch, ent=ent, webauth=_webauth())
    r = client.post("/auth", json={"user": "alice", "pass": "pw"}, headers=_origin())
    assert r.status_code == 429
    assert r.headers["Retry-After"] == "120"
    ent.record_failure.assert_not_called()


def test_bad_password_counts_a_failure(client, monkeypatch):
    wa = _webauth()
    wa.verify.return_value = None
    ent = _ent_mod()
    _wire(monkeypatch, ent=ent, webauth=wa)
    r = client.post("/auth", json={"user": "alice", "pass": "nope"}, headers=_origin())
    assert r.status_code == 401
    ent.record_failure.assert_called_once_with("alice")


def test_bad_token_counts_a_failure_against_the_token_account(client, monkeypatch):
    ent = _ent_mod()
    _wire(monkeypatch, ent=ent)
    r = client.post("/auth", json={"token": "wrong"}, headers=_origin())
    assert r.status_code == 401
    ent.record_failure.assert_called_once_with(netwatch._TOKEN_ACCOUNT)


def test_locked_token_account_blocks_the_fixed_token(client, monkeypatch):
    ent = _ent_mod(lockout_state=MagicMock(
        return_value={"locked": True, "retry_after": 60}))
    _wire(monkeypatch, ent=ent)
    r = client.post("/auth", json={"token": netwatch.WEB_TOKEN}, headers=_origin())
    assert r.status_code == 429


def test_lockout_ledger_failure_never_breaks_login(client, monkeypatch):
    ent = _ent_mod(record_success=MagicMock(side_effect=OSError("disk full")),
                   lockout_state=MagicMock(side_effect=OSError("disk full")))
    _wire(monkeypatch, ent=ent)
    r = client.post("/auth", json={"token": netwatch.WEB_TOKEN}, headers=_origin())
    assert r.status_code == 200


# ── sessions: epoch, idle, rolling refresh ──────────────────────────────────

def _authed_session(client, monkeypatch, ent, role="admin", user="alice"):
    _wire(monkeypatch, ent=ent, webauth=_webauth(role))
    client.set_cookie("nw_sess", netwatch._mint_session(user, role), path="/")


def test_session_dies_when_the_epoch_moves(client, monkeypatch):
    ent = _ent_mod()
    _authed_session(client, monkeypatch, ent)
    assert client.get("/api/state").status_code == 200
    ent.session_epoch.return_value = 1        # "sign out other devices"
    assert client.get("/api/state").status_code == 401


def test_session_dies_after_the_idle_timeout(client, monkeypatch):
    ent = _ent_mod()
    _wire(monkeypatch, ent=ent, webauth=_webauth("admin"))
    stale = netwatch._fernet.encrypt(json.dumps(
        {"u": "alice", "r": "admin", "e": 0,
         "s": time.time() - netwatch._SESSION_IDLE - 60,
         "exp": time.time() + 3600}).encode()).decode()
    client.set_cookie("nw_sess", stale, path="/")
    assert client.get("/api/state").status_code == 401


def test_active_session_is_refreshed_on_each_request(client, monkeypatch):
    ent = _ent_mod()
    _authed_session(client, monkeypatch, ent)
    before = client.get_cookie("nw_sess").value
    assert client.get("/api/state").status_code == 200
    assert client.get_cookie("nw_sess").value != before      # rolling stamp


def test_epoch_check_fails_closed(client, monkeypatch):
    ent = _ent_mod(session_epoch=MagicMock(side_effect=OSError("boom")))
    _authed_session(client, monkeypatch, ent)
    assert client.get("/api/state").status_code == 401


def test_token_cookie_ttl_is_enforced(client, monkeypatch):
    _wire(monkeypatch, tier="free")
    client.post("/auth", json={"token": netwatch.WEB_TOKEN}, headers=_origin())
    assert client.get("/api/state").status_code == 200
    monkeypatch.setattr(netwatch, "_TOKEN_COOKIE_TTL", -1)   # every cookie is stale
    assert client.get("/api/state").status_code == 401


# ── logout ──────────────────────────────────────────────────────────────────

def test_logout_clears_both_cookies(client, monkeypatch):
    _wire(monkeypatch, tier="free")
    client.post("/auth", json={"token": netwatch.WEB_TOKEN}, headers=_origin())
    r = client.post("/logout", headers=_origin())
    assert r.status_code == 200
    assert client.get("/api/state").status_code == 401


def test_logout_by_get_works_too(client, monkeypatch):
    _wire(monkeypatch, tier="free")
    client.post("/auth", json={"token": netwatch.WEB_TOKEN}, headers=_origin())
    r = client.get("/logout")
    assert r.status_code in (302, 303)
    assert client.get("/api/state").status_code == 401


def test_logout_is_audited(client, monkeypatch):
    events = []
    monkeypatch.setattr(netwatch, "audit_emit",
                        lambda action, detail=None, actor="local": events.append(action))
    _wire(monkeypatch, tier="free")
    client.post("/auth", json={"token": netwatch.WEB_TOKEN}, headers=_origin())
    client.post("/logout", headers=_origin())
    assert "web.logout" in events and "web.login.ok" in events


def test_failed_logins_are_audited(client, monkeypatch):
    events = []
    monkeypatch.setattr(netwatch, "audit_emit",
                        lambda action, detail=None, actor="local": events.append(action))
    _wire(monkeypatch, tier="free")
    client.post("/auth", json={"token": "wrong"}, headers=_origin())
    assert "web.login.fail" in events


# ── API keys ────────────────────────────────────────────────────────────────

def test_api_key_grants_its_scope(client, monkeypatch):
    ent = _ent_mod(verify_api_key=MagicMock(
        return_value={"id": "a1", "name": "ci", "scope": "read", "role": "viewer"}))
    _wire(monkeypatch, ent=ent)
    r = client.get("/api/state", headers={"X-NetWatch-Key": "nwk_a1_secret"})
    assert r.status_code == 200


def test_invalid_api_key_gets_the_login_page(client, monkeypatch):
    ent = _ent_mod()
    _wire(monkeypatch, ent=ent)
    r = client.get("/api/state", headers={"X-NetWatch-Key": "nwk_a1_wrong"})
    assert r.status_code == 401


def test_api_key_role_is_enforced_on_commands(client, monkeypatch):
    ent = _ent_mod(verify_api_key=MagicMock(
        return_value={"id": "a1", "name": "ci", "scope": "read", "role": "viewer"}))
    _wire(monkeypatch, ent=ent)
    r = client.post("/api/cmd", json={"cmd": "block 1.2.3.4"},
                    headers={"X-NetWatch-Key": "nwk_a1_secret"})
    assert r.status_code == 403        # viewer scope can't run operator commands


def test_api_key_post_does_not_need_an_origin_header(client, monkeypatch):
    ent = _ent_mod(verify_api_key=MagicMock(
        return_value={"id": "a1", "name": "ci", "scope": "operator",
                      "role": "operator"}))
    _wire(monkeypatch, ent=ent)
    r = client.post("/api/cmd", json={"cmd": "status"},
                    headers={"X-NetWatch-Key": "nwk_a1_secret"})
    assert r.status_code == 200


def test_cookie_post_still_needs_an_origin_header(client, monkeypatch):
    _wire(monkeypatch, tier="free")
    client.post("/auth", json={"token": netwatch.WEB_TOKEN}, headers=_origin())
    r = client.post("/api/cmd", json={"cmd": "status"})
    assert r.status_code == 403


def test_api_keys_are_ignored_below_enterprise(client, monkeypatch):
    ent = _ent_mod(verify_api_key=MagicMock(
        return_value={"role": "operator", "scope": "operator"}))
    _wire(monkeypatch, ent=ent, tier="pro")
    r = client.get("/api/state", headers={"X-NetWatch-Key": "nwk_a1_secret"})
    assert r.status_code == 401
    ent.verify_api_key.assert_not_called()


def test_api_key_verified_once_per_request(client, monkeypatch):
    ent = _ent_mod(verify_api_key=MagicMock(
        return_value={"id": "a1", "name": "ci", "scope": "operator",
                      "role": "operator"}))
    _wire(monkeypatch, ent=ent)
    client.post("/api/cmd", json={"cmd": "status"},
                headers={"X-NetWatch-Key": "nwk_a1_secret"})
    assert ent.verify_api_key.call_count == 1


# ── proxy-aware client IP ───────────────────────────────────────────────────

def test_xff_ignored_by_default(client, monkeypatch):
    monkeypatch.delenv("NETWATCH_TRUST_PROXY", raising=False)
    _wire(monkeypatch, tier="free")
    with netwatch.web_app.test_request_context(
            "/", headers={"X-Forwarded-For": "9.9.9.9"},
            environ_base={"REMOTE_ADDR": "127.0.0.1"}):
        assert netwatch._client_ip() == "127.0.0.1"


def test_xff_used_when_the_operator_opts_in(client, monkeypatch):
    monkeypatch.setenv("NETWATCH_TRUST_PROXY", "1")
    with netwatch.web_app.test_request_context(
            "/", headers={"X-Forwarded-For": "1.1.1.1, 9.9.9.9"},
            environ_base={"REMOTE_ADDR": "127.0.0.1"}):
        assert netwatch._client_ip() == "9.9.9.9"     # rightmost hop, not the spoofable one


def test_bogus_xff_falls_back_to_remote_addr(client, monkeypatch):
    monkeypatch.setenv("NETWATCH_TRUST_PROXY", "1")
    with netwatch.web_app.test_request_context(
            "/", headers={"X-Forwarded-For": "not-an-ip"},
            environ_base={"REMOTE_ADDR": "127.0.0.1"}):
        assert netwatch._client_ip() == "127.0.0.1"


def test_allowlist_still_uses_remote_addr(client, monkeypatch):
    """Trusting XFF for the allowlist would let anyone forge an allowed source."""
    monkeypatch.setenv("NETWATCH_TRUST_PROXY", "1")
    _wire(monkeypatch, tier="free")
    r = client.get("/api/state", environ_overrides={"REMOTE_ADDR": "8.8.8.8"},
                   headers={"X-Forwarded-For": "127.0.0.1"})
    assert r.status_code == 403


# ── headers ─────────────────────────────────────────────────────────────────

def test_csp_header_is_present(client, monkeypatch):
    _wire(monkeypatch, tier="free")
    r = client.get("/api/state")
    csp = r.headers.get("Content-Security-Policy", "")
    assert "default-src 'self'" in csp and "object-src 'none'" in csp
    assert "frame-ancestors 'self'" in csp


# ── SSO ─────────────────────────────────────────────────────────────────────

def _sso_mod(**kw):
    mod = MagicMock()
    mod.configured.return_value = True
    mod.begin_login.return_value = {"url": "https://idp.example.com/authorize?x=1",
                                    "state": "st", "nonce": "no",
                                    "verifier": "ver", "issued_at": time.time()}
    mod.complete_login.return_value = {"user": "alice", "email": "a@b.c",
                                       "role": "operator", "sub": "s1",
                                       "claims": {}}
    for k, v in kw.items():
        setattr(mod, k, v)
    return mod


def test_login_page_offers_sso_when_configured(client, monkeypatch):
    _wire(monkeypatch, sso=_sso_mod())
    r = client.get("/")
    assert r.status_code == 401 and b"/auth/oidc/login" in r.data


def test_login_page_hides_sso_when_not_configured(client, monkeypatch):
    _wire(monkeypatch, sso=_sso_mod(configured=MagicMock(return_value=False)))
    r = client.get("/")
    assert b"/auth/oidc/login" not in r.data


def test_oidc_login_redirects_and_stores_the_pending_state(client, monkeypatch):
    sso = _sso_mod()
    _wire(monkeypatch, sso=sso)
    r = client.get("/auth/oidc/login")
    assert r.status_code in (302, 303)
    assert r.headers["Location"].startswith("https://idp.example.com/authorize")
    pending = json.loads(netwatch._fernet.decrypt(
        client.get_cookie("nw_oidc", path="/auth/oidc").value.encode()).decode())
    assert pending["state"] == "st" and pending["verifier"] == "ver"


def test_oidc_callback_mints_a_session(client, monkeypatch):
    sso = _sso_mod()
    _wire(monkeypatch, ent=_ent_mod(), sso=sso, webauth=_webauth("operator"))
    client.get("/auth/oidc/login")
    r = client.get("/auth/oidc/callback?code=abc&state=st")
    assert r.status_code in (302, 303)
    assert client.get_cookie("nw_sess") is not None
    assert sso.complete_login.call_args[0][2] == "st"


def test_sso_session_survives_the_next_request(client, monkeypatch):
    """Regression: SSO users are NOT in the local RBAC store, so revalidating
    the session against webauth.current_role bounced every SSO login on its
    very next request. The callback succeeding is not enough — the cookie must
    still authenticate a follow-up request."""
    ent = _ent_mod()
    wa = _webauth("operator")
    wa.current_role.return_value = None      # SSO slug is absent from web_users.json
    _wire(monkeypatch, ent=ent, sso=_sso_mod(), webauth=wa)
    client.get("/auth/oidc/login")
    client.get("/auth/oidc/callback?code=abc&state=st")
    assert client.get("/api/state").status_code == 200
    assert client.get("/api/state").status_code == 200      # and again


def test_sso_session_is_revoked_by_epoch_bump(client, monkeypatch):
    """`mfa signout <user>` must still kill an SSO session immediately."""
    ent = _ent_mod()
    wa = _webauth("operator"); wa.current_role.return_value = None
    _wire(monkeypatch, ent=ent, sso=_sso_mod(), webauth=wa)
    client.get("/auth/oidc/login")
    client.get("/auth/oidc/callback?code=abc&state=st")
    assert client.get("/api/state").status_code == 200
    ent.session_epoch.return_value = 1       # signed out everywhere
    assert client.get("/api/state").status_code == 401


def test_sso_session_honours_the_idle_timeout(client, monkeypatch):
    ent = _ent_mod()
    wa = _webauth("operator"); wa.current_role.return_value = None
    _wire(monkeypatch, ent=ent, sso=_sso_mod(), webauth=wa)
    client.get("/auth/oidc/login")
    client.get("/auth/oidc/callback?code=abc&state=st")
    monkeypatch.setattr(netwatch, "_SESSION_IDLE", -1)   # everything is idle now
    assert client.get("/api/state").status_code == 401


def test_local_rbac_user_is_still_revalidated_every_request(client, monkeypatch):
    """The SSO carve-out must NOT weaken local users: a demotion in the store
    still takes effect immediately."""
    ent = _ent_mod()
    wa = _webauth("admin")
    _wire(monkeypatch, ent=ent, webauth=wa)
    client.post("/auth", json={"user": "alice", "pass": "pw"}, headers=_origin())
    assert client.get("/api/state").status_code == 200
    wa.current_role.return_value = None      # removed from the store
    assert client.get("/api/state").status_code == 401


def test_oidc_callback_without_a_pending_login_is_refused(client, monkeypatch):
    sso = _sso_mod()
    _wire(monkeypatch, sso=sso)
    r = client.get("/auth/oidc/callback?code=abc&state=st")
    assert r.status_code == 401
    sso.complete_login.assert_not_called()


def test_oidc_callback_surfaces_a_refused_login(client, monkeypatch):
    sso = _sso_mod(complete_login=MagicMock(
        side_effect=ValueError("no NetWatch role is mapped for this account")))
    _wire(monkeypatch, sso=sso)
    client.get("/auth/oidc/login")
    r = client.get("/auth/oidc/callback?code=abc&state=st")
    assert r.status_code == 401
    assert b"no NetWatch role is mapped" in r.data
    assert client.get_cookie("nw_sess") is None


def test_oidc_idp_error_is_not_a_login(client, monkeypatch):
    _wire(monkeypatch, sso=_sso_mod())
    client.get("/auth/oidc/login")
    r = client.get("/auth/oidc/callback?error=access_denied")
    assert r.status_code == 401
    assert client.get_cookie("nw_sess") is None


def test_sso_routes_are_enterprise_gated(client, monkeypatch):
    _wire(monkeypatch, sso=_sso_mod(), tier="pro")
    assert client.get("/auth/oidc/login").status_code == 402
    assert client.get("/auth/oidc/callback?code=a&state=b").status_code == 402


def test_sso_failure_does_not_break_the_login_page(client, monkeypatch):
    _wire(monkeypatch, sso=_sso_mod(configured=MagicMock(side_effect=OSError("boom"))))
    r = client.get("/")
    assert r.status_code == 401 and b"NETWATCH" in r.data


# ── TUI / CLI verbs ─────────────────────────────────────────────────────────

def _console(monkeypatch):
    out = []
    monkeypatch.setattr(netwatch, "add_console",
                        lambda line="", *a, **k: out.append(line))
    return out


def _text(lines):
    return " ".join(netwatch._ansi_strip(str(l)) for l in lines)


def test_mfa_verb_is_enterprise_gated(monkeypatch):
    ent = _ent_mod()
    _wire(monkeypatch, ent=ent, tier="pro")
    out = _console(monkeypatch)
    netwatch._disp_mfa(["mfa"])
    assert "Enterprise" in _text(out)
    ent.mfa_status.assert_not_called()


def test_mfa_status_lists_users(monkeypatch):
    ent = _ent_mod(mfa_status=MagicMock(return_value=[
        {"user": "alice", "enrolled": True, "confirmed": True,
         "recovery_left": 9, "locked_until": 0, "failures": 0,
         "last_login": None, "epoch": 0}]))
    _wire(monkeypatch, ent=ent)
    out = _console(monkeypatch)
    netwatch._disp_mfa(["mfa"])
    assert "alice" in _text(out) and "recovery left: 9" in _text(out)


def test_mfa_enroll_prints_secret_and_codes(monkeypatch):
    ent = _ent_mod(enroll_totp=MagicMock(return_value={
        "user": "alice", "secret": "ABCDEF", "uri": "otpauth://totp/x",
        "recovery_codes": ["aaaa-bbbb-cccc-dddd"]}))
    _wire(monkeypatch, ent=ent)
    out = _console(monkeypatch)
    netwatch._disp_mfa(["mfa", "enroll", "alice"])
    text = _text(out)
    assert "ABCDEF" in text and "aaaa-bbbb-cccc-dddd" in text
    assert "mfa confirm alice" in text


def test_mfa_confirm_reports_a_bad_code(monkeypatch):
    ent = _ent_mod(confirm_totp=MagicMock(return_value=False))
    _wire(monkeypatch, ent=ent)
    out = _console(monkeypatch)
    netwatch._disp_mfa(["mfa", "confirm", "alice", "000000"])
    assert "rejected" in _text(out)


def test_mfa_signout_bumps_the_epoch(monkeypatch):
    ent = _ent_mod(bump_epoch=MagicMock(return_value=3))
    _wire(monkeypatch, ent=ent)
    out = _console(monkeypatch)
    netwatch._disp_mfa(["mfa", "signout", "alice"])
    ent.bump_epoch.assert_called_once_with("alice")
    assert "signed out" in _text(out)


def test_mfa_verb_never_raises(monkeypatch):
    ent = _ent_mod(mfa_status=MagicMock(side_effect=RuntimeError("boom")))
    _wire(monkeypatch, ent=ent)
    out = _console(monkeypatch)
    netwatch._disp_mfa(["mfa"])
    assert "RuntimeError" in _text(out)


def test_apikey_new_prints_the_key_once(monkeypatch):
    ent = _ent_mod(mint_api_key=MagicMock(return_value={
        "id": "abc123", "name": "ci-bot", "scope": "read",
        "expires": None, "key": "nwk_abc123_supersecret"}))
    _wire(monkeypatch, ent=ent)
    out = _console(monkeypatch)
    netwatch._disp_apikey(["apikey", "new", "ci-bot", "read"])
    ent.mint_api_key.assert_called_once_with("ci-bot", "read", None)
    assert "nwk_abc123_supersecret" in _text(out)


def test_apikey_new_accepts_a_ttl(monkeypatch):
    ent = _ent_mod(mint_api_key=MagicMock(return_value={
        "id": "a", "name": "n", "scope": "operator", "expires": 1, "key": "k"}))
    _wire(monkeypatch, ent=ent)
    _console(monkeypatch)
    netwatch._disp_apikey(["apikey", "new", "n", "operator", "30"])
    ent.mint_api_key.assert_called_once_with("n", "operator", 30)


def test_apikey_rejects_a_bad_scope(monkeypatch):
    ent = _ent_mod(mint_api_key=MagicMock(side_effect=ValueError("scope must be …")))
    _wire(monkeypatch, ent=ent)
    out = _console(monkeypatch)
    netwatch._disp_apikey(["apikey", "new", "n", "admin"])
    assert "scope must be" in _text(out)


def test_apikey_list_and_revoke(monkeypatch):
    ent = _ent_mod(list_api_keys=MagicMock(return_value=[
        {"id": "abc123", "name": "ci-bot", "scope": "read",
         "created": "t", "expires": None, "last_used": None, "revoked": False}]),
        revoke_api_key=MagicMock(return_value=True))
    _wire(monkeypatch, ent=ent)
    out = _console(monkeypatch)
    netwatch._disp_apikey(["apikey"])
    assert "abc123" in _text(out) and "ci-bot" in _text(out)
    out2 = _console(monkeypatch)
    netwatch._disp_apikey(["apikey", "revoke", "abc123"])
    assert "Revoked" in _text(out2)


def test_sso_verb_reports_the_config(monkeypatch):
    sso = _sso_mod(config_summary=MagicMock(return_value={
        "issuer": "https://idp.example.com", "client_id": "cid",
        "redirect_uri": "https://nw/cb", "role_claim": "groups",
        "roles_mapped": ["admins"], "allowed_domains": []}))
    _wire(monkeypatch, sso=sso)
    out = _console(monkeypatch)
    netwatch._disp_sso(["sso"])
    text = _text(out)
    assert "idp.example.com" in text and "admins" in text


def test_sso_verb_when_unconfigured(monkeypatch):
    sso = _sso_mod(configured=MagicMock(return_value=False))
    _wire(monkeypatch, sso=sso)
    out = _console(monkeypatch)
    netwatch._disp_sso(["sso"])
    assert "not configured" in _text(out)


def test_enterprise_verbs_are_registered_as_cli_subcommands():
    for verb in ("mfa", "apikey", "sso"):
        assert verb in netwatch._CLI_SUBCOMMANDS


def test_enterprise_verbs_are_not_web_runnable():
    """They print one-time secrets — the web console must not be able to."""
    for verb in ("mfa", "apikey", "sso"):
        assert verb not in netwatch._WEB_SAFE_CMDS


def test_cli_shim_routes_to_the_verb(monkeypatch, capsys):
    ent = _ent_mod(mfa_status=MagicMock(return_value=[]))
    _wire(monkeypatch, ent=ent)
    assert netwatch._cli_via_console(netwatch._disp_mfa, ["mfa"]) == 0
    assert "No users have MFA enrolled" in netwatch._ansi_strip(capsys.readouterr().out)


def test_cli_shim_restores_add_console(monkeypatch):
    original = netwatch.add_console
    _wire(monkeypatch, ent=_ent_mod(mfa_status=MagicMock(side_effect=RuntimeError())))
    netwatch._cli_via_console(netwatch._disp_mfa, ["mfa"])
    assert netwatch.add_console is original
