"""Testes da metade de coleta/normalização (Galazzi).

Cobre: parsing de ExecStart/argv, flags de modo, nonroot_writable (inclusive o
caso do diretório-pai), ancestralidade (inclusive pai ausente), eventos de login
e serviço na linha do tempo, e os parsers de services.txt e journal.log.

Rode a partir da raiz do repositório:
    python3 -m unittest tests.test_normalize
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from investigator import collect_dataset, normalize
from investigator.collect_dataset import RawDataset
from investigator.model import FileInfo


def _fileinfo(path, owner="root", group="root", mode=0o644, type="file"):
    flags = normalize.mode_flags(mode)
    return FileInfo(
        path=path, type=type, owner=owner, group=group, mode=mode, mtime=None,
        world_writable=flags["world_writable"], group_writable=flags["group_writable"],
        suid=flags["suid"], sgid=flags["sgid"],
        nonroot_writable=None, nonroot_reason="", src=path,
    )


class ExecStartArgvTest(unittest.TestCase):
    def test_strip_systemd_prefix(self):
        self.assertEqual(normalize.strip_systemd_prefix("-/usr/bin/foo"), "/usr/bin/foo")
        self.assertEqual(normalize.strip_systemd_prefix("@+/bin/x"), "/bin/x")
        self.assertEqual(normalize.strip_systemd_prefix("/bin/x"), "/bin/x")

    def test_exe_is_argv0(self):
        exe, script = normalize.extract_paths("/usr/sbin/sshd -D")
        self.assertEqual(exe, "/usr/sbin/sshd")
        self.assertIsNone(script)

    def test_interpreter_script_is_first_absolute_arg(self):
        exe, script = normalize.extract_paths("/bin/bash /opt/backup/backup.sh")
        self.assertEqual(exe, "/bin/bash")
        self.assertEqual(script, "/opt/backup/backup.sh")

    def test_python_interpreter_versioned(self):
        exe, script = normalize.extract_paths("/usr/bin/python3 /opt/monitor/agent.py")
        self.assertEqual(exe, "/usr/bin/python3")
        self.assertEqual(script, "/opt/monitor/agent.py")

    def test_execstart_prefix_then_interpreter(self):
        exe, script = normalize.extract_paths("-/bin/bash /opt/x/run.sh")
        self.assertEqual(exe, "/bin/bash")
        self.assertEqual(script, "/opt/x/run.sh")


class ModeFlagsTest(unittest.TestCase):
    def test_world_writable(self):
        self.assertTrue(normalize.mode_flags(0o777)["world_writable"])
        self.assertFalse(normalize.mode_flags(0o755)["world_writable"])

    def test_group_writable(self):
        self.assertTrue(normalize.mode_flags(0o770)["group_writable"])
        self.assertFalse(normalize.mode_flags(0o755)["group_writable"])

    def test_suid_sgid(self):
        self.assertTrue(normalize.mode_flags(0o4755)["suid"])
        self.assertTrue(normalize.mode_flags(0o2755)["sgid"])
        self.assertFalse(normalize.mode_flags(0o0755)["suid"])

    def test_parse_mode_octal(self):
        self.assertEqual(normalize.parse_mode("0777"), 0o777)
        self.assertEqual(normalize.parse_mode("4755"), 0o4755)
        self.assertIsNone(normalize.parse_mode("xyz"))


class NonrootWritableTest(unittest.TestCase):
    def test_world_writable_is_others_w(self):
        fi = _fileinfo("/opt/a/x.sh", mode=0o777)
        w, reason = normalize.compute_nonroot_writable(fi, {fi.path: fi}, live=False, group_members=None)
        self.assertTrue(w)
        self.assertEqual(reason, "others:w")

    def test_owner_not_root(self):
        fi = _fileinfo("/home/aluno/x", owner="aluno", mode=0o755)
        w, reason = normalize.compute_nonroot_writable(fi, {fi.path: fi}, live=False, group_members=None)
        self.assertTrue(w)
        self.assertEqual(reason, "owner=aluno")

    def test_group_writable_nonroot_group_dataset(self):
        fi = _fileinfo("/opt/a/x", group="staff", mode=0o770)
        w, reason = normalize.compute_nonroot_writable(fi, {fi.path: fi}, live=False, group_members=None)
        self.assertTrue(w)
        self.assertIn("grupo=staff", reason)

    def test_group_root_is_safe(self):
        fi = _fileinfo("/opt/a/x", group="root", mode=0o770)
        w, reason = normalize.compute_nonroot_writable(fi, {fi.path: fi}, live=False, group_members=None)
        self.assertFalse(w)

    def test_shadow_is_safe(self):
        fi = _fileinfo("/etc/shadow", group="shadow", mode=0o640)
        w, _ = normalize.compute_nonroot_writable(fi, {fi.path: fi}, live=False, group_members=None)
        self.assertFalse(w)

    def test_parent_directory_makes_file_writable(self):
        parent = _fileinfo("/opt/backup", mode=0o777, type="directory")
        script = _fileinfo("/opt/backup/backup.sh", mode=0o755)
        files = {parent.path: parent, script.path: script}
        w, reason = normalize.compute_nonroot_writable(script, files, live=False, group_members=None)
        self.assertTrue(w)
        self.assertEqual(reason, "dir /opt/backup 0777")

    def test_live_group_without_nonroot_member_is_safe(self):
        fi = _fileinfo("/opt/a/x", group="svc", mode=0o770)
        w, _ = normalize.compute_nonroot_writable(
            fi, {fi.path: fi}, live=True, group_members={"svc": {"root"}})
        self.assertFalse(w)

    def test_live_group_with_nonroot_member_is_writable(self):
        fi = _fileinfo("/opt/a/x", group="svc", mode=0o770)
        w, reason = normalize.compute_nonroot_writable(
            fi, {fi.path: fi}, live=True, group_members={"svc": {"root", "aluno"}})
        self.assertTrue(w)
        self.assertIn("grupo=svc", reason)


class AncestryTest(unittest.TestCase):
    def _snap(self, procs, perms=None, logs=None):
        raw = RawDataset(
            source="dataset", host="h", processes=procs,
            permissions=perms or [], services=[], logs=logs or [], gaps=[])
        return normalize.build_snapshot(raw)

    def test_chain_up_to_pid1(self):
        procs = [
            {"pid": "1", "ppid": "0", "user": "root", "stat": "Ss", "cmd": "/sbin/init", "src": "x:1"},
            {"pid": "10", "ppid": "1", "user": "root", "stat": "Ss", "cmd": "/usr/sbin/sshd -D", "src": "x:2"},
            {"pid": "20", "ppid": "10", "user": "aluno", "stat": "S", "cmd": "/bin/bash", "src": "x:3"},
        ]
        snap = self._snap(procs)
        self.assertEqual(snap.processes[20].ancestry, [10, 1])
        self.assertEqual(snap.processes[10].ancestry, [1])

    def test_missing_parent_is_recorded_in_gaps(self):
        procs = [
            {"pid": "1234", "ppid": "900", "user": "root", "stat": "S", "cmd": "/bin/bash", "src": "x:1"},
        ]
        snap = self._snap(procs)
        self.assertEqual(snap.processes[1234].ancestry, [900])
        self.assertTrue(any("PPID 900 de PID 1234 ausente" in g for g in snap.gaps))

    def test_cycle_does_not_hang(self):
        procs = [
            {"pid": "2", "ppid": "3", "user": "root", "stat": "S", "cmd": "/bin/a", "src": "x:1"},
            {"pid": "3", "ppid": "2", "user": "root", "stat": "S", "cmd": "/bin/b", "src": "x:2"},
        ]
        snap = self._snap(procs)  # não deve travar
        self.assertIn(3, snap.processes[2].ancestry)


class TimelineTest(unittest.TestCase):
    def _snap_from_logs(self, log_rows, procs=None, perms=None):
        from investigator.model import LogEvent
        logs = [LogEvent(ts=ts, ident=ident, pid=pid, unit=None, message=msg, src=src)
                for (ts, ident, pid, msg, src) in log_rows]
        raw = RawDataset(source="dataset", host="h", processes=procs or [],
                         permissions=perms or [], services=[], logs=logs, gaps=[])
        return normalize.build_snapshot(raw)

    def test_login_event(self):
        snap = self._snap_from_logs([
            ("2026-09-14T09:01:40", "sshd", 2630,
             "Accepted publickey for aluno from 10.20.30.44 port 51518 ssh2", "journal.log:1"),
        ])
        logins = [e for e in snap.timeline if e.kind == "login"]
        self.assertEqual(len(logins), 1)
        self.assertEqual(logins[0].subject, "aluno")
        self.assertEqual(logins[0].detail["ip"], "10.20.30.44")
        self.assertEqual(logins[0].detail["method"], "publickey")

    def test_session_event_strips_period(self):
        snap = self._snap_from_logs([
            ("2026-09-14T09:01:42", "systemd-logind", 640,
             "New session 9 of user aluno.", "journal.log:2"),
        ])
        sessions = [e for e in snap.timeline if e.kind == "session"]
        self.assertEqual(sessions[0].subject, "aluno")

    def test_service_start_and_stop(self):
        snap = self._snap_from_logs([
            ("2026-09-14T09:00:00", "systemd", 1,
             "Started ssh.service - OpenBSD Secure Shell server.", "journal.log:1"),
            ("2026-09-14T09:05:00", "systemd", 1,
             "backup-agent.service: Deactivated successfully.", "journal.log:2"),
        ])
        kinds = {(e.kind, e.subject) for e in snap.timeline}
        self.assertIn(("service_start", "ssh.service"), kinds)
        self.assertIn(("service_stop", "backup-agent.service"), kinds)

    def test_timeline_sorted_by_time(self):
        snap = self._snap_from_logs([
            ("2026-09-14T09:05:00", "systemd", 1, "Started b.service", "journal.log:2"),
            ("2026-09-14T09:00:00", "systemd", 1, "Started a.service", "journal.log:1"),
        ])
        ts = [e.ts for e in snap.timeline if e.ts]
        self.assertEqual(ts, sorted(ts))

    def test_file_mtime_event(self):
        perms = [{"path": "/opt/x/run.sh", "type": "file", "owner": "root",
                  "group": "root", "mode": "0777", "mtime": "2026-09-14T09:03:20",
                  "src": "permissions.csv:2"}]
        snap = self._snap_from_logs([], perms=perms)
        mtimes = [e for e in snap.timeline if e.kind == "file_mtime"]
        self.assertEqual(mtimes[0].subject, "/opt/x/run.sh")


class DatasetParserTest(unittest.TestCase):
    def test_services_txt_split_maxsplit(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "services.txt"
            p.write_text(
                "UNIT                         ACTIVE   USER      EXECSTART\n"
                "a-really-long-unit-name.service running root      /bin/bash /opt/x/run.sh with args\n",
                encoding="utf-8")
            rows = collect_dataset._parse_services(Path(d), [])
        self.assertEqual(rows[0]["unit"], "a-really-long-unit-name.service")
        self.assertEqual(rows[0]["active"], "running")
        self.assertEqual(rows[0]["user"], "root")
        self.assertEqual(rows[0]["exec_start"], "/bin/bash /opt/x/run.sh with args")
        self.assertEqual(rows[0]["src"], "services.txt:2")

    def test_journal_parse_and_year_resolution(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "journal.log").write_text(
                "Sep 14 09:00:00 srv-app-01 systemd[1]: Started ssh.service - x.\n"
                "Sep 14 09:01:40 srv-app-01 sshd[2630]: Accepted publickey for aluno from 10.20.30.44 port 5 ssh2\n",
                encoding="utf-8")
            logs, host = collect_dataset._parse_journal(Path(d), 2026, [])
        self.assertEqual(host, "srv-app-01")
        self.assertEqual(logs[0].ident, "systemd")
        self.assertEqual(logs[0].pid, 1)
        self.assertEqual(logs[0].ts, "2026-09-14T09:00:00")
        self.assertEqual(logs[1].ident, "sshd")
        self.assertEqual(logs[1].pid, 2630)

    def test_to_naive_iso_strips_offset(self):
        self.assertEqual(collect_dataset.to_naive_iso("2026-09-14T09:03:20-03:00"),
                         "2026-09-14T09:03:20")
        self.assertEqual(collect_dataset.to_naive_iso("2026-09-14T09:03:20"),
                         "2026-09-14T09:03:20")
        self.assertIsNone(collect_dataset.to_naive_iso("not-a-date"))


class ProcessServiceMappingTest(unittest.TestCase):
    def test_execstart_exact_match_ppid1(self):
        procs = [
            {"pid": "1", "ppid": "0", "user": "root", "stat": "Ss", "cmd": "/sbin/init", "src": "x:1"},
            {"pid": "2417", "ppid": "1", "user": "root", "stat": "Ss",
             "cmd": "/bin/bash /opt/backup/backup.sh", "src": "x:2"},
        ]
        services = [{"unit": "backup-agent.service", "active": "running", "user": "root",
                     "exec_start": "/bin/bash /opt/backup/backup.sh", "src": "services.txt:2"}]
        raw = RawDataset(source="dataset", host="h", processes=procs,
                         permissions=[], services=services, logs=[], gaps=[])
        snap = normalize.build_snapshot(raw)
        self.assertEqual(snap.processes[2417].unit, "backup-agent.service")
        self.assertEqual(snap.processes[2417].unit_method, "execstart")

    def test_name_match_weak(self):
        procs = [
            {"pid": "1", "ppid": "0", "user": "root", "stat": "Ss", "cmd": "/sbin/init", "src": "x:1"},
            {"pid": "733", "ppid": "1", "user": "www-data", "stat": "S",
             "cmd": "/usr/sbin/apache2 -k start", "src": "x:2"},
        ]
        services = [{"unit": "apache2.service", "active": "running", "user": "root",
                     "exec_start": "/usr/sbin/apachectl start", "src": "services.txt:2"}]
        raw = RawDataset(source="dataset", host="h", processes=procs,
                         permissions=[], services=services, logs=[], gaps=[])
        snap = normalize.build_snapshot(raw)
        self.assertEqual(snap.processes[733].unit, "apache2.service")
        self.assertEqual(snap.processes[733].unit_method, "name")


if __name__ == "__main__":
    unittest.main()
