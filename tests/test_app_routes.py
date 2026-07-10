"""Route-level tests for webui/app.py, via the Flask test client.

These are only possible because create_app() made `import app` side-effect-free:
the module can now be imported under pytest without touching /opt/gatecrash, and
the auth-state file paths are monkeypatched into a tmp dir so each test is
isolated. This is the first coverage of the actual web layer (auth gate, CSRF,
setup-mode lockdown) rather than the extracted pure helpers.

Run from the repo root with:  pytest
"""

import pytest


@pytest.fixture
def client(tmp_path, monkeypatch):
    import app
    import devices

    # Set a session secret directly (create_app() would read a file); keep the
    # import side-effect-free path — we don't want _init_logging touching disk.
    app.app.secret_key = "test-secret-key"
    app.app.config["TESTING"] = True
    app.limiter.enabled = False  # don't let the 5/min login limit flake tests

    # Redirect every auth-state file into tmp so tests touch no real files and
    # don't leak state between each other.
    monkeypatch.setattr(app, "WEBUI_TOKEN_PATH", str(tmp_path / "token"))
    monkeypatch.setattr(app, "NO_AUTH_PATH", str(tmp_path / "no_auth"))
    monkeypatch.setattr(app, "HTTPS_PREF_PATH", str(tmp_path / "https_pref"))
    monkeypatch.setattr(app, "WELCOME_PATH", str(tmp_path / "welcome"))
    monkeypatch.setattr(devices, "DEVICES_FILE", str(tmp_path / "devices.json"))
    return app.app.test_client()


# ---------------------------------------------------------------------------
# Setup mode — no password set yet, no no-auth marker
# ---------------------------------------------------------------------------

def test_setup_mode_locks_down_protected_api(client):
    # CRIT-7: before setup is complete, every /api/* except the setup endpoints
    # is refused.
    assert client.get("/api/saved-devices").status_code == 403


def test_setup_mode_serves_index(client):
    # The setup screen itself must render.
    assert client.get("/").status_code == 200


# ---------------------------------------------------------------------------
# Login flow (password configured)
# ---------------------------------------------------------------------------

def test_unauthenticated_protected_api_is_401_once_token_exists(client):
    import app
    app._store_password("correct-horse-battery")
    assert client.get("/api/saved-devices").status_code == 401


def test_login_rejects_wrong_password(client):
    import app
    app._store_password("correct-horse-battery")
    r = client.post("/api/login", json={"password": "wrong"})
    assert r.status_code == 200
    assert r.get_json()["ok"] is False


def test_login_accepts_correct_password_and_unlocks(client):
    import app
    app._store_password("correct-horse-battery")
    r = client.post("/api/login", json={"password": "correct-horse-battery"})
    body = r.get_json()
    assert body["ok"] is True
    assert "csrf_token" in body
    # The test client keeps the session cookie, so the protected API opens up.
    assert client.get("/api/saved-devices").status_code == 200


# ---------------------------------------------------------------------------
# CSRF — mutating POSTs need the double-submit token, even after login
# ---------------------------------------------------------------------------

def test_csrf_required_on_mutating_post(client):
    import app
    app._store_password("pw-abcdefgh")
    csrf = client.post("/api/login", json={"password": "pw-abcdefgh"}).get_json()["csrf_token"]
    # No CSRF header → rejected.
    assert client.post("/api/logout").status_code == 403
    # With the token → accepted.
    assert client.post("/api/logout", headers={"X-CSRF-Token": csrf}).status_code == 200


def test_dns_log_route_returns_entries(client):
    # Exercises the watchdogs.dns_log_snapshot() path through the route.
    import app
    app._store_password("pw-abcdefgh")
    client.post("/api/login", json={"password": "pw-abcdefgh"})
    r = client.get("/api/dns-log")
    assert r.status_code == 200
    assert "entries" in r.get_json()
