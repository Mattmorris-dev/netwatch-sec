"""The `ask` command + `collector model` dispatch wiring (honeypot side).

The ask/model LOGIC lives in netwatch_pro and is tested there; here we test only
that netwatch.py dispatches, parses --provider, gates on Pro, and renders output.
"""
import netwatch


class _FakeAsk:
    """Stand-in for netwatch_pro.ask — records how it was called."""
    last = {}

    @staticmethod
    def ask(question, *, provider="local", **kw):
        _FakeAsk.last = {"question": question, "provider": provider}
        return {"question": question, "provider": provider,
                "answer": f"answer about {question}\nline two",
                "citations": ["[1.1.1.1 · ssh · novelty 90]"],
                "llm": None}


def _cap(monkeypatch):
    out = []
    monkeypatch.setattr(netwatch, "add_console", lambda *a, **k: out.append(a[0] if a else ""))
    return out


def test_disp_ask_local_renders_answer(monkeypatch):
    monkeypatch.setattr(netwatch, "tier_at_least", lambda t: True)
    monkeypatch.setattr(netwatch, "_pro_sub", lambda n: _FakeAsk if n == "ask" else None)
    out = _cap(monkeypatch)
    netwatch._disp_ask(["ask", "what", "is", "the", "ftp", "attacker"])
    text = "\n".join(out)
    assert _FakeAsk.last["question"] == "what is the ftp attacker"
    assert _FakeAsk.last["provider"] == "local"          # default
    assert "answer about" in text and "line two" in text


def test_disp_ask_parses_provider_flag(monkeypatch):
    monkeypatch.setattr(netwatch, "tier_at_least", lambda t: True)
    monkeypatch.setattr(netwatch, "_pro_sub", lambda n: _FakeAsk if n == "ask" else None)
    _cap(monkeypatch)
    netwatch._disp_ask(["ask", "mongo", "probe", "--provider", "anthropic"])
    assert _FakeAsk.last["provider"] == "anthropic"
    assert _FakeAsk.last["question"] == "mongo probe"     # flag stripped from question


def test_disp_ask_free_tier_blocked(monkeypatch):
    monkeypatch.setattr(netwatch, "tier_at_least", lambda t: False)
    called = []
    monkeypatch.setattr(netwatch, "_pro_sub", lambda n: called.append(n) or None)
    out = _cap(monkeypatch)
    netwatch._disp_ask(["ask", "anything"])
    assert not called                                    # never loads the Pro module
    assert any("Pro feature" in l for l in out)


def test_disp_ask_empty_question_shows_usage(monkeypatch):
    monkeypatch.setattr(netwatch, "tier_at_least", lambda t: True)
    monkeypatch.setattr(netwatch, "_pro_sub", lambda n: _FakeAsk if n == "ask" else None)
    out = _cap(monkeypatch)
    netwatch._disp_ask(["ask", "--provider", "local"])   # no question words
    assert any("usage:" in l for l in out)


def test_ask_registered_in_cli_and_modules(monkeypatch):
    assert "ask" in netwatch._CLI_SUBCOMMANDS
    monkeypatch.setattr(netwatch, "tier_at_least", lambda t: True)
    monkeypatch.setattr(netwatch, "_pro_sub", lambda n: object() if n == "ask" else None)
    assert "ask" in netwatch.pro_active_modules()


def test_cli_ask_subcommand(monkeypatch, capsys):
    monkeypatch.setattr(netwatch, "tier_at_least", lambda t: True)
    monkeypatch.setattr(netwatch, "_pro_sub", lambda n: _FakeAsk if n == "ask" else None)
    rc = netwatch._cli_subcommand(["ask", "what", "is", "happening"])
    assert rc == 0
    assert "answer about what is happening" in capsys.readouterr().out


def test_cli_ask_empty_question_usage(monkeypatch, capsys):
    monkeypatch.setattr(netwatch, "tier_at_least", lambda t: True)
    monkeypatch.setattr(netwatch, "_pro_sub", lambda n: _FakeAsk if n == "ask" else None)
    rc = netwatch._cli_subcommand(["ask"])
    assert rc == 1 and "usage:" in capsys.readouterr().out


class _FakeCollector:
    def __init__(self, *a, **k): pass
    def stage_model(self, path):
        return {"staged": str(path), "bytes": 79, "sha256": "abc123def456ghi"}
    def model_status(self):
        return {"staged": True, "path": "/x/model.json", "bytes": 79,
                "sha256": "abc123def456ghi", "mtime": "2026-07-11T00:00:00+00:00"}


class _FakeCollectorMod:
    Collector = _FakeCollector
    DEFAULT_PORT = 8443


def test_collector_model_stage_and_status(monkeypatch):
    monkeypatch.setattr(netwatch, "tier_at_least", lambda t: True)
    monkeypatch.setattr(netwatch, "_pro_sub",
                        lambda n: _FakeCollectorMod if n == "collector" else None)
    monkeypatch.setattr(netwatch, "_apiary_collector", None, raising=False)
    out = _cap(monkeypatch)
    netwatch._disp_collector(["collector", "model", "/tmp/edge.json"])
    netwatch._disp_collector(["collector", "model"])
    text = "\n".join(out)
    assert "staged" in text.lower() and "abc123def456" in text
