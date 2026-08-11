"""capture-poc.py `_clean_for_display`: the raw issued Bash line -> the REAL command(s) that go
into poc/cmdlog/. Unwrap the vm.sh/rsh transport, decode literal base64 cradles, drop cd/echo-banner
and local-state-read noise, and return '' when nothing meaningful is left (so the entry is skipped).
Pure-function tests, no I/O."""
import base64
import importlib.util
import os

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOK = os.path.join(REPO, "skills", "hooks", "capture-poc.py")


def _load():
    spec = importlib.util.spec_from_file_location("capture_poc", HOOK)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


clean = _load()._clean_for_display


def test_plain_command_unchanged():
    assert clean("nmap -sCV 10.1.1.5") == "nmap -sCV 10.1.1.5"


def test_unwraps_vm_sh_transport():
    assert clean("bash /root/vm.sh 'nmap -sV 10.1.1.5'") == "nmap -sV 10.1.1.5"


def test_strips_cd_and_echo_banner_noise():
    assert clean('cd /x && echo "=== scan ===" ; nmap -p- 10.1.1.5') == "nmap -p- 10.1.1.5"


def test_all_noise_returns_empty():
    # cd + echo banner + a local state-file read -> nothing worth logging
    assert clean('cd /x && echo "=== state ===" ; cat targets/acme/state.md') == ""


def test_strips_local_md_read_only():
    assert clean("cat targets/acme/loot.md") == ""


def test_keeps_remote_cat_as_loot():
    # a remote read (via vm.sh) of a target file is loot, not local-state noise -> survives
    assert clean("bash /root/vm.sh 'cat /etc/shadow'") == "cat /etc/shadow"


def test_echo_feeding_a_pipe_is_kept_by_its_sink():
    # `echo <x> | base64 -d | nc ...` is an nc command, not an echo banner (var b64 undecodable)
    out = clean('bash /root/vm.sh "echo $P | base64 -d | nc 10.1.1.5 1337"')
    assert out == "echo $P | base64 -d | nc 10.1.1.5 1337"


def test_decodes_literal_base64_bash_cradle():
    b = base64.b64encode(b"id").decode()
    assert clean("echo %s | base64 -d | bash" % b) == "id"


def test_splits_chain_keeps_meaningful_only():
    b64 = base64.b64encode(b"whoami").decode()
    out = clean("cd /x && echo hi ; nmap 10.1.1.5 ; echo %s | base64 -d | bash" % b64)
    assert out == "nmap 10.1.1.5\nwhoami"


def test_compound_for_loop_kept_intact():
    # a spray/brute loop is ONE command; its internal `;` must not be split across lines
    out = clean('bash /root/vm.sh "for u in a b; do sshpass -p x ssh $u@10.1.1.5 id; done"')
    assert out == "for u in a b; do sshpass -p x ssh $u@10.1.1.5 id; done"


def test_semicolon_inside_quotes_not_split():
    # a `;` inside a quoted SQLi payload must not split the command
    out = clean("bash /root/vm.sh \"sqlmap -u 'http://h/?q=1;DROP' --batch\"")
    assert out == "sqlmap -u 'http://h/?q=1;DROP' --batch"
