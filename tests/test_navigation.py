"""Navigation: help covers every command, help search, typo suggestions, and a
guard that stops the command tables from drifting apart again."""
import inspect
import re

import netwatch

# Other spellings of a documented command. A new command needs a help entry;
# a new alias needs a line here. The test below fails for anything else.
ALIASES = {
    "abusers": "attacks", "threats": "attacks", "checkme": "expose", "droplet": "remote",
    "cameras": "cam", "apikeys": "apikey", "deps": "doctor", "check": "doctor",
    "dash": "dashboard", "commandline": "cli", "command-line": "cli",
    "token": "show-token", "showtunnel": "tunnel", "show-tunnel": "tunnel",
    "changetunnel": "restart-tunnel", "change-tunnel": "restart-tunnel",
    "new-tunnel": "restart-tunnel",
}


def _dispatch_names():
    src = inspect.getsource(netwatch.handle_command)
    names = set(re.findall(r'action == "([a-z0-9\-?]+)"', src))
    for group in re.findall(r'action in \(([^)]*)\)', src):
        names |= set(re.findall(r'"([a-z0-9\-?]+)"', group))
    names |= set(re.findall(r'"([a-z0-9\-]+)":\s*\(\d', src))
    return names


def _norm(word):
    return word.replace("-", "")


class TestHelpCoverage:
    def test_dispatch_parser_sees_the_commands(self):
        names = _dispatch_names()
        assert len(names) > 100 and {"scan", "cve", "geo", "block", "doctor", "help"} <= names

    def test_every_command_is_in_help_or_is_a_known_alias(self):
        helped = {_norm(w) for w in netwatch._help_command_words()}
        missing = sorted(n for n in _dispatch_names()
                         if _norm(n) not in helped and n not in netwatch._TAB_NAMES and n not in ALIASES)
        assert missing == [], f"add a help entry (or an ALIASES line) for: {missing}"

    def test_aliases_point_at_documented_commands(self):
        helped = {_norm(w) for w in netwatch._help_command_words()}
        assert [a for a, target in ALIASES.items() if _norm(target) not in helped] == []

    def test_web_and_role_tables_name_real_commands(self):
        known = _dispatch_names() | netwatch._TAB_NAMES
        for table in ("_WEB_SAFE_CMDS", "_CMD_MIN_ROLE", "_EXPENSIVE_CMDS", "_OUTBOUND_CMDS"):
            unknown = sorted(c for c in getattr(netwatch, table) if c not in known)
            assert unknown == [], f"{table} names commands that do not exist: {unknown}"

    def test_web_help_lists_cve(self):
        assert '["cve &lt;ip|CVE-id&gt;"' in netwatch.WEB_DASHBOARD_HTML


class TestHelpSearch:
    def _out(self):
        return "\n".join(netwatch.console_output)

    def test_search_by_command(self):
        netwatch.handle_command("help cve")
        assert "cve <ip|CVE-id>" in self._out() and "[Scanning]" in self._out()

    def test_search_by_description(self):
        netwatch.handle_command("help traceroute")
        assert "trace <ip>" in self._out()

    def test_no_match_suggests(self):
        netwatch.handle_command("help portscn")
        assert "No help entry" in self._out() and "portscan" in self._out()

    def test_plain_help_is_unchanged(self):
        netwatch.handle_command("help")
        assert "COMMAND REFERENCE" in self._out()
        netwatch.show_help_overlay = False

    def test_search_term_is_sanitised(self):
        netwatch.handle_command("help \x1b[2Jzzzz")
        assert "\x1b[2J" not in self._out()


class TestUnknownCommand:
    def test_typo_gets_a_suggestion(self):
        netwatch.handle_command("portscn 1.2.3.4")
        out = "\n".join(netwatch.console_output)
        assert "Unknown: 'portscn'." in out and "Did you mean: portscan" in out

    def test_nonsense_gets_no_suggestion(self):
        netwatch.handle_command("zzqqxx")
        out = "\n".join(netwatch.console_output)
        assert "Unknown: 'zzqqxx'. Type 'help'" in out
