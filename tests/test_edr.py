# testes da camada EDR (monitor comportamental). Nada malicioso e executado.

import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path

import psutil

from antiv import config
from antiv.edr import response
from antiv.edr.files import CanaryManager, FsEvent, RansomwareDetector
from antiv.edr.models import ProcInfo, level_for_score
from antiv.edr.monitor import BehaviorMonitor, MonitorOptions
from antiv.edr.network import BeaconDetector, Conn, evaluate_network
from antiv.edr.persistence import PersistenceWatcher, diff_snapshots, evaluate_persistence
from antiv.edr.rules import BehaviorRules, evaluate_process
from antiv.edr.telemetry import Telemetry

RULES = BehaviorRules.load()
MARKER = config.TEST_MARKER


def proc(name, cmd="", exe="", pid=100, ppid=50, ctime=1000.0):
    return ProcInfo(pid, ppid, name, exe, cmd, ctime)


def ids(dets):
    return {d.rule_id for d in dets}


def score(dets):
    return min(100, sum(d.points for d in dets))


class RuleTests(unittest.TestCase):
    def test_office_spawning_encoded_powershell(self):
        parent = proc("winword.exe", pid=50)
        child = proc("powershell.exe", "powershell.exe -nop -w hidden -enc " + "QQBB" * 12, pid=100)
        dets = evaluate_process(child, parent, RULES)
        self.assertTrue({"OFFICE-SHELL", "PS-ENCODED", "PS-HIDDEN"} <= ids(dets))
        self.assertEqual(level_for_score(score(dets)), "critico")

    def test_benign_process_has_no_detections(self):
        dets = evaluate_process(proc("notepad.exe", "notepad.exe C:\\a.txt",
                                     "C:\\Windows\\System32\\notepad.exe"), proc("explorer.exe"), RULES)
        self.assertEqual(dets, [])

    def test_shadow_copy_deletion(self):
        dets = evaluate_process(proc("cmd.exe", "cmd /c vssadmin delete shadows /all /quiet"), None, RULES)
        self.assertIn("RECOVERY-INHIBIT", ids(dets))
        self.assertEqual(level_for_score(score(dets)), "alto")

    def test_masquerading_svchost(self):
        child = proc("svchost.exe", "svchost.exe",
                     "C:\\Users\\a\\AppData\\Local\\Temp\\svchost.exe")
        dets = evaluate_process(child, proc("explorer.exe"), RULES)
        self.assertTrue({"MASQUERADE", "WRONG-PARENT", "RUN-FROM-TEMP"} <= ids(dets))

    def test_cmd_caret_obfuscation(self):
        dets = evaluate_process(proc("cmd.exe", "cmd /c " + "^a" * 15), None, RULES)
        self.assertIn("CMD-CARET-OBFUSC", ids(dets))

    def test_legit_powershell_script_is_not_flagged(self):
        dets = evaluate_process(proc("powershell.exe", "powershell -File C:\\scripts\\backup.ps1"), None, RULES)
        self.assertEqual(dets, [])


class NetworkTests(unittest.TestCase):
    def test_unexpected_network_use(self):
        conns = [Conn("ESTABLISHED", "192.168.0.5", 50000, "8.8.8.8", 443)]
        self.assertIn("NET-UNEXPECTED", ids(evaluate_network(proc("notepad.exe"), conns, RULES.never_network)))

    def test_private_destination_ignored(self):
        conns = [Conn("ESTABLISHED", "192.168.0.5", 50000, "192.168.0.1", 443)]
        self.assertEqual(evaluate_network(proc("notepad.exe"), conns, RULES.never_network), [])

    def test_beacon_detection(self):
        regular, irregular = BeaconDetector(), BeaconDetector()
        hit = None
        for i in range(8):                      # reaparece a cada 30 s
            regular.update("k", set(), i * 30 - 1)
            hit = regular.update("k", {"203.0.113.9"}, i * 30) or hit
        self.assertIsNotNone(hit)
        times = [0, 7, 31, 40, 95, 101, 190, 250]
        got = None
        for t in times:
            irregular.update("k", set(), t - 1)
            got = irregular.update("k", {"203.0.113.9"}, t) or got
        self.assertIsNone(got)


class PersistenceTests(unittest.TestCase):
    def test_scoring(self):
        bad = evaluate_persistence(
            "run:HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
            "powershell -w hidden -enc QQBBQQBB C:\\Users\\a\\AppData\\Local\\Temp\\x.exe")
        good = evaluate_persistence("run:HKCU\\...\\Run\\App", '"C:\\Program Files\\App\\app.exe" --tray')
        self.assertGreaterEqual(score(bad), 70)
        self.assertLess(score(good), 40)

    def test_diff_and_watcher(self):
        self.assertEqual(diff_snapshots({"a": "1"}, {"a": "2", "b": "3"}),
                         [("a", "2", "alterado"), ("b", "3", "novo")])
        tmp = Path(tempfile.mkdtemp())
        try:
            snaps = iter([{"run:x": "C:\\ok.exe"},
                          {"run:x": "C:\\ok.exe",
                           "run:y": "powershell -w hidden -enc QQBBQQBB C:\\Users\\a\\AppData\\Local\\Temp\\z.exe"}])
            mon = BehaviorMonitor(MonitorOptions(telemetry_path=None))
            watcher = PersistenceWatcher(mon, lambda **k: next(snaps), tmp / "base.json")
            self.assertEqual(watcher.poll_once(), 0)          # 1a leitura = base
            self.assertEqual(watcher.poll_once(), 1)          # item novo
            self.assertEqual(len(mon.alerts), 1)
            self.assertEqual(mon.alerts[0].source, "persistencia")
        finally:
            shutil.rmtree(tmp)


class RansomwareTests(unittest.TestCase):
    def test_mass_encryption_rename_and_notes(self):
        det = RansomwareDetector(entropy_fn=lambda p: 0.99, entropy_files=10, ext_files=8, note_dirs=3)
        out = []
        for i in range(12):
            out += det.feed(FsEvent("moved", f"C:\\Docs\\a{i}.docx", f"C:\\Docs\\a{i}.docx.locked", ts=100 + i * 0.15))
        for d in ("A", "B", "C"):
            out += det.feed(FsEvent("created", os.path.join("docs", d, "LEIA-ME-DECRYPT.txt"), ts=102))
        self.assertTrue({"RANSOM-MASS-ENCRYPT", "RANSOM-MASS-RENAME", "RANSOM-NOTE"} <= ids(out))

    def test_normal_activity_is_quiet(self):
        det = RansomwareDetector(entropy_fn=lambda p: 0.4, entropy_files=10, ext_files=8)
        out = []
        for i in range(30):
            out += det.feed(FsEvent("modified", f"C:\\Docs\\n{i}.txt", ts=100 + i * 0.1))
        self.assertEqual(out, [])

    def test_canary_check(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            mgr = CanaryManager([str(tmp)], registry=tmp / "reg.json")
            files = mgr.create()
            mgr.created_at = 0
            self.assertEqual(len(files), len(CanaryManager.NAMES))
            self.assertIsNone(mgr.check(FsEvent("modified", files[0])))   # sem mudanca real
            Path(files[0]).write_bytes(b"cifrado!")
            self.assertEqual(mgr.check(FsEvent("modified", files[0])).rule_id, "CANARY-HIT")
            self.assertEqual(mgr.check(FsEvent("deleted", files[1])).points, 95)
        finally:
            shutil.rmtree(tmp)


class ResponseTests(unittest.TestCase):
    def test_protection_rules(self):
        self.assertTrue(response.is_protected(os.getpid())[0])
        self.assertTrue(response.is_protected(4)[0])
        self.assertTrue(response.is_protected(900, "lsass.exe", "C:\\Windows\\System32\\lsass.exe")[0])
        self.assertFalse(response.is_protected(900, "svchost.exe", "C:\\Users\\a\\AppData\\Local\\Temp\\svchost.exe")[0])
        self.assertFalse(response.terminate_process(os.getpid())[0])

    def test_triage_snapshot(self):
        data = response.collect_triage(os.getpid(), "teste")
        self.assertEqual(data["pid"], os.getpid())
        self.assertIn("ancestors", data)
        self.assertTrue(data["name"])

    def test_telemetry_ring_and_rotation(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            t = Telemetry(tmp / "t.jsonl", max_bytes=2000, keep=2)
            for i in range(60):
                t.log("x", i=i, pad="y" * 50)
            seq, fresh = t.since(55)
            self.assertEqual((seq, len(fresh)), (60, 5))
            t.close()
            self.assertTrue((tmp / "t.jsonl.1").exists())
        finally:
            shutil.rmtree(tmp)


def wait_for(cond, timeout=20.0):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.1)
    return False


class LiveMonitorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.procs = []

    def tearDown(self):
        for p in self.procs:
            try:
                response.terminate_process(p.pid)
                p.wait(timeout=3)
            except Exception:
                pass
        shutil.rmtree(self.tmp, ignore_errors=True)
        shutil.rmtree(config.INCIDENTS_DIR, ignore_errors=True)
        CanaryManager.remove_registered()

    def opts(self, **kw):
        base = dict(telemetry_path=None, watch_files=False, watch_persistence=False,
                    watch_network=False, proc_interval=0.1, prefer_watchdog=False,
                    poll_interval=0.2, scan_settle=0.2)
        base.update(kw)
        return MonitorOptions(**base)

    def test_process_alert_with_triage(self):
        mon = BehaviorMonitor(self.opts())
        mon.start()
        try:
            self.procs.append(mon.simulate_test())
            self.assertTrue(wait_for(lambda: any("TESTE" in a.techniques for a in mon.alerts)))
            alert = next(a for a in mon.alerts if "TESTE" in a.techniques)
            self.assertEqual(alert.level, "alto")
            self.assertEqual(alert.source, "processo")
            self.assertTrue(alert.incident and Path(alert.incident).exists())
        finally:
            mon.close()

    def test_auto_suspend_critical_and_resume(self):
        mon = BehaviorMonitor(self.opts(auto_suspend_critical=True))
        mon.start()
        try:
            p = mon.simulate_test(["vssadmin delete shadows /all"])
            self.procs.append(p)
            self.assertTrue(wait_for(lambda: any(a.level == "critico" for a in mon.alerts)))
            alert = next(a for a in mon.alerts if a.level == "critico")
            self.assertIn("suspenso", alert.action)
            self.assertTrue(wait_for(lambda: psutil.Process(p.pid).status() == psutil.STATUS_STOPPED, 5))
            self.assertTrue(response.resume_process(p.pid)[0])
        finally:
            mon.close()

    def test_no_auto_action_by_default_and_allowlist(self):
        mon = BehaviorMonitor(self.opts())
        mon.start()
        try:
            p = mon.simulate_test(["vssadmin delete shadows /all"])
            self.procs.append(p)
            self.assertTrue(wait_for(lambda: any(a.level == "critico" for a in mon.alerts)))
            self.assertEqual(psutil.Process(p.pid).status() != psutil.STATUS_STOPPED, True)
            self.assertEqual(next(a for a in mon.alerts if a.level == "critico").action, "nenhuma")
        finally:
            mon.close()

    def test_realtime_file_scan_and_auto_quarantine(self):
        mon = BehaviorMonitor(self.opts(watch_files=True, roots=[str(self.tmp)], hot_roots=[str(self.tmp)],
                                        auto_quarantine_files=True, watch_ransomware=False))
        mon.start()
        try:
            time.sleep(0.5)
            bad = self.tmp / "baixado.txt"
            bad.write_text(MARKER)
            self.assertTrue(wait_for(lambda: any(a.source == "arquivo" for a in mon.alerts), 15))
            alert = next(a for a in mon.alerts if a.source == "arquivo")
            self.assertEqual(alert.level, "critico")
            self.assertTrue(wait_for(lambda: not bad.exists(), 5))
            self.assertIn("isolado", alert.action)
        finally:
            mon.close()

    def test_canary_triggers_ransomware_alert(self):
        mon = BehaviorMonitor(self.opts(watch_files=True, roots=[str(self.tmp)], hot_roots=[],
                                        use_canaries=True, realtime_scan=False))
        mon.start()
        try:
            mon.files.canaries.created_at = 0
            time.sleep(0.5)
            victim = next(iter(mon.files.canaries.files.values()))[0]
            Path(victim).write_bytes(os.urandom(2048))
            self.assertTrue(wait_for(lambda: any(a.source == "ransomware" for a in mon.alerts), 15))
            alert = next(a for a in mon.alerts if a.source == "ransomware")
            self.assertEqual(alert.level, "critico")
            self.assertIn("T1486", alert.techniques)
        finally:
            mon.close()


if __name__ == "__main__":
    unittest.main()
