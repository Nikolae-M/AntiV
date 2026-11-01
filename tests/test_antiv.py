# testes do AntiV. Nenhum arquivo malicioso real e usado.
#
# As amostras de teste (EICAR e marcador do AntiV) sao montadas em tempo de
# execucao para que o codigo-fonte e os .pyc nao disparem antivirus

import hashlib
import os
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path

from antiv import config
from antiv.engine import ScanEngine, ScanOptions
from antiv.quarantine import QuarantineManager
from antiv.signatures import RuleSet, SignatureDB

# EICAR em hexadecimal (nao e o texto literal, entao o Defender ignora este arquivo)
EICAR = bytes.fromhex(
    "58354f2150254041505b345c505a58353428505e2937434329377d24"
    "45494341522d5354414e444152442d414e544956495255532d544553"
    "542d46494c452124482b482a"
).decode("ascii")
MARKER = config.TEST_MARKER


def build_pe(sections, entry_rva, with_imports=False):
    # monta um PE32 minimo (apenas cabecalhos + secoes) para testar heuristicas
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 64)
    opt = bytearray(224)
    struct.pack_into("<H", opt, 0, 0x10B)
    struct.pack_into("<I", opt, 16, entry_rva)
    struct.pack_into("<I", opt, 92, 16)
    if with_imports:
        struct.pack_into("<II", opt, 96 + 8, 0x3000, 100)
    coff = struct.pack("<HHIIIHH", 0x14C, len(sections), 0, 0, 0, 224, 0x0102)
    table, body = b"", b""
    for name, vaddr, vsize, rsize, flags, data in sections:
        table += struct.pack("<8sIIIIIIHHI", name, vsize, vaddr, rsize,
                             0x400 + len(body), 0, 0, 0, 0, flags)
        body += data.ljust(rsize, b"\0")
    header = bytes(dos) + b"PE\0\0" + coff + bytes(opt) + table
    return header.ljust(0x400, b"\0") + body


def scan(folder, **kw):
    opts = dict(low_priority=False, use_cache=False)
    opts.update(kw)
    engine = ScanEngine(ScanOptions(**opts))
    engine.run([str(folder)])
    return engine


class DetectionTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def names(self, engine):
        return {(f.name, f.level, f.method) for f in engine.report.findings}

    def test_marker_rule_and_clean_file(self):
        (self.dir / "a.txt").write_text(MARKER)
        (self.dir / "limpo.txt").write_text("arquivo normal")
        engine = scan(self.dir)
        self.assertEqual([f.name for f in engine.report.findings], ["AntiV-Test-File"])
        self.assertEqual(engine.report.files_scanned, 2)

    def test_hash_signature(self):
        content = b"conteudo inofensivo para teste de hash"
        (self.dir / "x.bin").write_bytes(content)
        db = SignatureDB()
        db.signatures[hashlib.sha256(content).hexdigest()] = "Teste-Hash"
        engine = ScanEngine(ScanOptions(low_priority=False, use_cache=False), db=db)
        engine.run([str(self.dir)])
        found = [(f.name, f.method) for f in engine.report.findings]
        self.assertIn(("Teste-Hash", "hash SHA-256"), found)

    def test_eicar_rule(self):
        (self.dir / "e.com").write_text(EICAR)
        engine = scan(self.dir)
        self.assertIn("EICAR-Test-File", {f.name for f in engine.report.findings})

    def test_powershell_encoded_script(self):
        (self.dir / "s.ps1").write_text("powershell -NoP -EncodedCommand SQBFAFgA")
        engine = scan(self.dir)
        self.assertIn("Script.PowerShell.ComandoCodificado", {f.name for f in engine.report.findings})

    def test_double_extension_and_disguised_pe(self):
        (self.dir / "fatura.pdf.exe").write_bytes(b"conteudo qualquer")
        pe = build_pe([(b".text", 0x1000, 0x200, 0x200, 0x60000020, b"x" * 64)], 0x1000, True)
        (self.dir / "foto.jpg").write_bytes(pe)
        engine = scan(self.dir)
        by_file = {os.path.basename(f.path): f for f in engine.report.findings}
        self.assertEqual(by_file["fatura.pdf.exe"].level, "suspeito")
        self.assertEqual(by_file["foto.jpg"].level, "suspeito")

    def test_packed_pe_is_suspicious_but_clean_pe_is_not(self):
        packed = build_pe([
            (b"UPX0", 0x1000, 0x4000, 0x200, 0xE0000080, b""),
            (b"UPX1", 0x5000, 0x2000, 0x4000, 0xE0000040, os.urandom(0x4000)),
        ], 0x5100)
        clean = build_pe([
            (b".text", 0x1000, 0x2000, 0x2000, 0x60000020, (b"codigo normal " * 600)[:0x2000]),
            (b".rdata", 0x3000, 0x200, 0x200, 0x40000040, b"dados"),
        ], 0x1000, with_imports=True)
        (self.dir / "packed.exe").write_bytes(packed)
        (self.dir / "clean.exe").write_bytes(clean)
        engine = scan(self.dir)
        flagged = {os.path.basename(f.path): f for f in engine.report.findings}
        self.assertIn("packed.exe", flagged)
        self.assertEqual(flagged["packed.exe"].level, "suspeito")
        self.assertNotIn("clean.exe", flagged)

    def test_inside_zip_and_nested_zip(self):
        inner = self.dir / "inner.zip"
        with zipfile.ZipFile(inner, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("deep/amostra.txt", MARKER)
        with zipfile.ZipFile(self.dir / "pacote.zip", "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("leia-me.txt", "oi")
            z.writestr("pasta/teste.txt", MARKER)
            z.write(inner, "aninhado.zip")
        inner.unlink()
        engine = scan(self.dir)
        inners = sorted(f.inner for f in engine.report.findings if f.name == "AntiV-Test-File")
        self.assertEqual(inners, ["aninhado.zip > deep/amostra.txt", "pasta/teste.txt"])

    def test_office_macro_is_observation(self):
        with zipfile.ZipFile(self.dir / "doc.docm", "w") as z:
            z.writestr("[Content_Types].xml", "<Types/>")
            z.writestr("word/vbaProject.bin", b"dados")
        engine = scan(self.dir)
        self.assertTrue(any(f.level == "info" for f in engine.report.findings))

    def test_autorun_inf(self):
        (self.dir / "autorun.inf").write_text("[autorun]\nopen=virus.exe\n")
        engine = scan(self.dir)
        self.assertIn("Worm.AutorunInf", {f.name for f in engine.report.findings})

    def test_large_file_head_tail_and_deep_stream(self):
        big = self.dir / "grande.bin"
        filler = b"A" * (config.FULL_READ_LIMIT + 5 * config.MB)
        mid = len(filler) // 2
        big.write_bytes(filler[:mid] + MARKER.encode() + filler[mid:])   # marcador no MEIO
        fast = scan(self.dir, mode="full")
        deep = scan(self.dir, mode="deep")
        self.assertEqual(len(fast.report.findings), 0)    # meio do arquivo nao e amostrado
        self.assertEqual([f.name for f in deep.report.findings], ["AntiV-Test-File"])

    def test_fast_mode_skips_non_risky(self):
        (self.dir / "nota.txt").write_text(MARKER)
        (self.dir / "run.bat").write_text(MARKER)
        engine = scan(self.dir, mode="fast")
        self.assertEqual(engine.report.files_skipped, 1)
        self.assertEqual(len(engine.report.findings), 1)

    def test_parallel_many_files_and_counts(self):
        for i in range(300):
            (self.dir / f"f{i}.dat").write_bytes(os.urandom(2048))
        (self.dir / "sub").mkdir()
        (self.dir / "sub" / "ruim.txt").write_text(MARKER)
        engine = scan(self.dir, workers=8)
        self.assertEqual(engine.report.files_scanned, 301)
        self.assertEqual(len(engine.report.findings), 1)
        self.assertEqual(engine.stats.snapshot()["files_done"], 301)

    def test_auto_quarantine_and_restore(self):
        sample = self.dir / "e.txt"
        sample.write_text(MARKER)
        engine = scan(self.dir, auto_quarantine=True)
        self.assertFalse(sample.exists())
        self.assertTrue(engine.report.findings[0].action.startswith("quarentena"))
        qm = QuarantineManager()
        qid = next(i for i, e in qm.list_items().items() if e["original_path"] == str(sample))
        qm.restore(qid)
        self.assertEqual(sample.read_text(), MARKER)

    def test_cache_skips_unchanged_clean_files(self):
        (self.dir / "a.txt").write_text("limpo")
        first = scan(self.dir, use_cache=True)
        second = scan(self.dir, use_cache=True)
        self.assertEqual(first.report.files_cached, 0)
        self.assertEqual(second.report.files_cached, 1)

    def test_cancel_returns_partial_report(self):
        for i in range(50):
            (self.dir / f"f{i}.txt").write_text("x")
        engine = ScanEngine(ScanOptions(low_priority=False, use_cache=False))
        engine.cancel()
        report = engine.run([str(self.dir)])
        self.assertTrue(report.cancelled)

    def test_rules_load(self):
        self.assertGreaterEqual(len(RuleSet.load().rules), 10)


if __name__ == "__main__":
    unittest.main()
