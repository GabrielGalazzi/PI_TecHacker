"""Testes de aceitação da metade de análise (Sardou).

Para cada cenário do gerador: cria o dataset em um diretório temporário, roda o
pipeline completo (coleta -> normalização -> correlação) e confere as conclusões
esperadas. Os casos sintéticos no fim cobrem regras que os datasets não exercitam.

Rode a partir da raiz do repositório:
    python3 -m unittest tests.test_scenarios
"""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

import generate_dataset
from investigator import __main__ as cli
from investigator import collect_dataset, correlate, normalize
from investigator.collect_dataset import RawDataset


def _generate(scenario: str, out_dir: Path, seed=None) -> None:
    with contextlib.redirect_stdout(io.StringIO()):
        generate_dataset.make_dataset("basic", seed, out_dir, scenario=scenario)


def _analyze(scenario: str, seed=None):
    with tempfile.TemporaryDirectory() as tmp:
        _generate(scenario, Path(tmp), seed)
        snap = normalize.build_snapshot(collect_dataset.collect(tmp))
    return snap, correlate.run(snap)


def _find(findings, conclusion, correlation=None, text=""):
    return [f for f in findings
            if f.conclusion == conclusion
            and (correlation is None or correlation in f.correlation)
            and text in f.title]


def _proc(pid, ppid, user, cmd):
    return {"pid": str(pid), "ppid": str(ppid), "user": user, "stat": "S", "cmd": cmd,
            "src": f"processes.csv:{pid}"}


class ScenarioTest(unittest.TestCase):
    def test_normal_has_no_risk(self):
        _snap, findings = _analyze("normal")
        self.assertEqual(_find(findings, "RISCO"), [])
        self.assertEqual(_find(findings, "INCONCLUSIVO"), [])
        self.assertTrue(_find(findings, "CONTEXTO_OK", "C3", "/etc/shadow"))

    def test_permission_is_misconfiguration_not_risk(self):
        _snap, findings = _analyze("permission")
        self.assertEqual(_find(findings, "RISCO"), [])
        found = _find(findings, "CONFIG_INADEQUADA", "C3", "/opt/reports/report.sh")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].severity, "baixa")
        self.assertTrue(any("crontab" in m for m in found[0].missing))

    def test_privileged_service_root_alone_is_not_a_finding(self):
        _snap, findings = _analyze("privileged_service")
        self.assertEqual(_find(findings, "RISCO"), [])
        self.assertTrue(_find(findings, "CONTEXTO_OK", "C1", "backup-agent.service"))
        self.assertTrue(_find(findings, "INCONCLUSIVO", "C2", "updates.example.invalid"))
        self.assertTrue(_find(findings, "INCONCLUSIVO", "C4", "backup-agent.service"))

    def test_correlation_root_service_with_writable_script(self):
        _snap, findings = _analyze("correlation")
        risk = _find(findings, "RISCO", "C1", "backup-agent.service")
        self.assertEqual(len(risk), 1)
        self.assertEqual(risk[0].severity, "alta")
        self.assertEqual(risk[0].confidence, "alta")
        self.assertIn("anterior ao login de aluno", risk[0].interpretation)
        self.assertIn("NÃO prova exploração", risk[0].hypothesis)
        self.assertTrue(_find(findings, "INCONCLUSIVO", "C3", "/usr/local/bin/report-sync"))

    def test_ambiguous_outbound_is_not_concluded(self):
        _snap, findings = _analyze("ambiguous")
        self.assertEqual(_find(findings, "RISCO"), [])
        self.assertTrue(_find(findings, "CONTEXTO_OK", "C1", "monitor-agent.service"))
        outbound = _find(findings, "INCONCLUSIVO", "C2", "metrics.example.invalid")
        self.assertEqual(len(outbound), 1)
        self.assertIn("Não há base para concluir", outbound[0].hypothesis)

    def test_tampered_after_login_adds_temporal_context(self):
        _snap, findings = _analyze("tampered_after_login")
        risk = _find(findings, "RISCO", "C4", "backup-agent.service")
        self.assertEqual(len(risk), 1)
        self.assertEqual(risk[0].confidence, "alta")
        self.assertIn("posterior ao login de aluno", risk[0].interpretation)
        self.assertIn("pode já ter sido executado como root", risk[0].hypothesis)

    def test_writable_parent_dir_cites_the_directory(self):
        _snap, findings = _analyze("writable_parent_dir")
        risk = _find(findings, "RISCO", "C1", "backup-agent.service")
        self.assertEqual(len(risk), 1)
        self.assertTrue(any(e.text.startswith("/opt/backup directory") for e in risk[0].evidence))
        # o diretório já foi explicado em C1: C3 não o reporta de novo
        self.assertEqual(_find(findings, "CONFIG_INADEQUADA"), [])

    def test_user_to_root_without_sudo_in_chain(self):
        _snap, findings = _analyze("user_to_root")
        risk = _find(findings, "RISCO", "C2", "PID 2650")
        self.assertEqual(len(risk), 1)
        self.assertIn("bash(2638,aluno)", risk[0].chain)
        self.assertIn("bash(2650,root)", risk[0].chain)

    def test_missing_evidence_is_inconclusive(self):
        _snap, findings = _analyze("missing_evidence")
        self.assertEqual(_find(findings, "RISCO"), [])
        found = _find(findings, "INCONCLUSIVO", "C1", "/opt/x/run.sh")
        self.assertEqual(len(found), 1)
        self.assertTrue(any("permissões de /opt/x/run.sh" in m for m in found[0].missing))

    def test_random_only_flags_world_writable_mode(self):
        for seed in range(1, 25):
            snap, findings = _analyze("random", seed=seed)
            script = next(f for f in snap.files.values() if f.path.endswith("/run.sh"))
            with self.subTest(seed=seed, mode=oct(script.mode)):
                self.assertEqual(bool(_find(findings, "RISCO", "C1")), script.mode == 0o777)

    def test_every_finding_has_the_four_parts(self):
        for scenario in generate_dataset.SCENARIOS:
            _snap, findings = _analyze(scenario)
            for f in findings:
                with self.subTest(scenario=scenario, finding=f.title):
                    self.assertTrue(f.evidence and f.interpretation and f.hypothesis)
                    self.assertTrue(all(e.src and e.kind for e in f.evidence))
                    if f.conclusion != "CONTEXTO_OK":
                        self.assertTrue(f.missing)
                    if f.conclusion == "RISCO":
                        self.assertGreaterEqual(len({e.kind for e in f.evidence}), 2)


class RuleTest(unittest.TestCase):
    def _snap(self, processes, permissions=(), services=()):
        raw = RawDataset(processes=list(processes), permissions=list(permissions),
                         services=list(services))
        return normalize.build_snapshot(raw)

    def test_sudo_in_chain_is_expected_context(self):
        snap = self._snap([
            _proc(1, 0, "root", "/sbin/init"),
            _proc(100, 1, "aluno", "/bin/bash"),
            _proc(101, 100, "root", "/usr/bin/sudo -i"),
            _proc(102, 101, "root", "/bin/bash"),
        ])
        findings = correlate.run(snap)
        self.assertEqual(_find(findings, "RISCO"), [])
        self.assertTrue(_find(findings, "CONTEXTO_OK", "C2", "sudo"))

    @staticmethod
    def _live(pid, ppid, user, uid, euid, exe, cmd):
        row = _proc(pid, ppid, user, cmd)
        row.update(uid=uid, euid=euid, exe=exe, src=f"/proc/{pid}/status")
        return row

    def test_live_sudo_parent_is_expected_context(self):
        # Cadeia real (live): sudo segue vivo como pai, com o UID real do usuário.
        snap = self._snap([
            self._live(1, 0, "root", 0, 0, "/usr/lib/systemd/systemd", "/sbin/init"),
            self._live(100, 1, "aluno", 1000, 1000, "/usr/bin/bash", "bash"),
            self._live(101, 100, "aluno", 1000, 0, "/usr/bin/sudo", "sudo python3 -m x"),
            self._live(102, 101, "aluno", 1000, 0, "/usr/bin/sudo", "sudo python3 -m x"),
            self._live(103, 102, "root", 0, 0, "/usr/bin/python3.10", "python3 -m x"),
        ])
        findings = correlate.run(snap)
        self.assertEqual(_find(findings, "RISCO"), [])
        self.assertTrue(_find(findings, "CONTEXTO_OK", "C2", "via sudo (PID 103)"))

    def test_sudo_name_outside_system_dirs_is_not_trusted(self):
        snap = self._snap([
            self._live(1, 0, "root", 0, 0, "/usr/lib/systemd/systemd", "/sbin/init"),
            self._live(100, 1, "aluno", 1000, 1000, "/usr/bin/bash", "bash"),
            self._live(101, 100, "aluno", 1000, 0, "/tmp/sudo", "/tmp/sudo"),
            self._live(102, 101, "root", 0, 0, "/usr/bin/bash", "bash"),
        ])
        findings = correlate.run(snap)
        self.assertEqual(_find(findings, "CONTEXTO_OK", "C2", "via sudo"), [])
        # só a fonte "processo": RISCO é rebaixado, mas a transição continua apontada
        self.assertTrue(_find(findings, "INCONCLUSIVO", "C2", "PID 102"))

    def test_curl_name_alone_is_not_a_finding(self):
        # curl de um usuário comum, fora de serviço root: o nome não basta.
        snap = self._snap([
            _proc(1, 0, "root", "/sbin/init"),
            _proc(100, 1, "aluno", "/bin/bash"),
            _proc(101, 100, "aluno", "/usr/bin/curl -fsS https://example.invalid/x"),
        ])
        self.assertEqual(correlate.run(snap), [])

    def test_root_process_in_user_writable_location(self):
        snap = self._snap(
            [_proc(1, 0, "root", "/sbin/init"),
             _proc(200, 1, "root", "/bin/bash /home/aluno/job.sh")],
            permissions=[{"path": "/home/aluno/job.sh", "type": "file", "owner": "aluno",
                          "group": "aluno", "mode": "0755", "mtime": "",
                          "src": "permissions.csv:2"}])
        risk = _find(correlate.run(snap), "RISCO", "C2", "/home/aluno/job.sh")
        self.assertEqual(len(risk), 1)

    def test_single_source_risk_is_downgraded(self):
        snap = self._snap(
            [_proc(1, 0, "root", "/sbin/init")],
            permissions=[{"path": "/etc/shadow", "type": "file", "owner": "root",
                          "group": "shadow", "mode": "0666", "mtime": "",
                          "src": "permissions.csv:2"}])
        findings = correlate.run(snap)
        self.assertEqual(_find(findings, "RISCO"), [])
        self.assertTrue(_find(findings, "CONFIG_INADEQUADA", "C3", "/etc/shadow"))

    def test_sticky_parent_dir_is_not_replaceable(self):
        snap = self._snap(
            [_proc(1, 0, "root", "/sbin/init")],
            permissions=[
                {"path": "/tmp", "type": "directory", "owner": "root", "group": "root",
                 "mode": "1777", "mtime": "", "src": "permissions.csv:2"},
                {"path": "/tmp/job.sh", "type": "file", "owner": "root", "group": "root",
                 "mode": "0700", "mtime": "", "src": "permissions.csv:3"}])
        self.assertFalse(snap.files["/tmp/job.sh"].nonroot_writable)


class CliTest(unittest.TestCase):
    def _run(self, scenario):
        with tempfile.TemporaryDirectory() as tmp:
            data, out = Path(tmp) / "data", Path(tmp) / "out"
            _generate(scenario, data)
            with contextlib.redirect_stdout(io.StringIO()) as stdout:
                code = cli.main(["--dataset", str(data), "--out", str(out)])
            report = json.loads((out / "report.json").read_text(encoding="utf-8"))
            self.assertTrue((out / "report.md").is_file())
        return code, stdout.getvalue(), report

    def test_exit_code_1_when_risk(self):
        code, text, report = self._run("correlation")
        self.assertEqual(code, 1)
        self.assertEqual(report["summary"]["conclusions"]["RISCO"], 1)
        for part in ("EVIDÊNCIA (observado)", "INTERPRETAÇÃO", "HIPÓTESE", "EVIDÊNCIA AUSENTE"):
            self.assertIn(part, text)

    def test_exit_code_0_without_risk(self):
        code, _text, report = self._run("privileged_service")
        self.assertEqual(code, 0)
        self.assertEqual(report["summary"]["conclusions"]["RISCO"], 0)

    def test_exit_code_2_on_missing_dataset(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(["--dataset", "/nonexistent/dataset"]), 2)


if __name__ == "__main__":
    unittest.main()
