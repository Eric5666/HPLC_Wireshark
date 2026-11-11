#!/usr/bin/env python3
"""Tests for scripts/update_json_sha256.py (stdlib unittest, no Qt needed).

Run: python3 unit_test/ci/update-json-sha256/test_update_json_sha256.py
"""
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
SCRIPT = os.path.join(REPO, "scripts", "update_json_sha256.py")
HEX64 = re.compile(r"^[0-9a-f]{64}$")   # same rule as Downloader::verifyDownload


def run(*args, cwd):
    return subprocess.run([sys.executable, SCRIPT, *args], cwd=cwd,
                          capture_output=True, text=True)


class UpdateJsonSha256Test(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name
        # start from the real repo manifest so the schema stays in sync
        with open(os.path.join(REPO, "update.json"), encoding="utf-8") as f:
            self.orig = json.load(f)
        self.manifest = os.path.join(self.d, "update.json")
        with open(self.manifest, "w", encoding="utf-8") as f:
            json.dump(self.orig, f, ensure_ascii=False)
        self.win = os.path.join(self.d, "BPLC_STA_Monitor_Setup_v9.9.9.exe")
        self.lin = os.path.join(self.d, "BPLC_STA_Monitor_v9.9.9_linux_x86_64.tar.gz")
        with open(self.win, "wb") as f:
            f.write(b"windows-installer" * 1000)
        with open(self.lin, "wb") as f:
            f.write(b"linux-tarball" * 777)

    def tearDown(self):
        self.tmp.cleanup()

    def load(self):
        with open(self.manifest, encoding="utf-8") as f:
            return json.load(f)

    def test_patches_sha_url_version(self):
        base = "https://github.com/aron566/HPLC_Wireshark/releases/download/v9.9.9"
        sums = os.path.join(self.d, "SHA256SUMS.txt")
        r = run("--manifest", self.manifest, "--version", "9.9.9", "--base-url", base,
                "--sums", sums, f"windows={self.win}", f"linux={self.lin}", cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        m = self.load()["updates"]
        for key, path in (("windows", self.win), ("linux", self.lin)):
            with open(path, "rb") as f:
                digest = hashlib.sha256(f.read()).hexdigest()
            self.assertRegex(m[key]["sha256"], HEX64)
            self.assertEqual(m[key]["sha256"], digest)
            self.assertEqual(m[key]["download-url"], base + "/" + os.path.basename(path))
            self.assertEqual(m[key]["latest-version"], "9.9.9")
            # untouched fields survive
            self.assertEqual(m[key]["changelog"], self.orig["updates"][key]["changelog"])
            with open(sums, encoding="utf-8") as f:
                self.assertIn(f"{digest}  {os.path.basename(path)}", f.read())

    def test_rejects_url_pointing_elsewhere(self):
        # without --base-url the existing URL (v2.0.1 asset) does not match
        r = run("--manifest", self.manifest, f"windows={self.win}", cwd=self.d)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("does not point at", r.stderr)
        self.assertNotIn("sha256", self.load()["updates"]["windows"])

    def test_missing_package_fails(self):
        r = run("--manifest", self.manifest, "--base-url", "https://x/y",
                "linux=" + os.path.join(self.d, "nope.tar.gz"), cwd=self.d)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("not found", r.stderr)

    def test_only_named_platform_changes(self):
        r = run("--manifest", self.manifest, "--base-url", "https://x/y",
                f"linux={self.lin}", cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.load()["updates"]["windows"], self.orig["updates"]["windows"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
