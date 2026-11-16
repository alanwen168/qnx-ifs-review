import json
import tempfile
import unittest
from pathlib import Path

import ifs_review


class ReviewTests(unittest.TestCase):
    def parse_bytes(self, data: bytes, explicit_prefix=True):
        if explicit_prefix:
            data = b"[prefix=proc/boot]\n" + data
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "input.build"
            p.write_bytes(data)
            return ifs_review.parse(p)

    def test_attribute_scope_and_default_prefix(self):
        r = self.parse_bytes(b"[uid=0]\n[gid=1] a=x\nb=y\n")
        self.assertEqual(r["entries"][0]["attributes"], {"prefix": "proc/boot", "uid": "0", "gid": "1"})
        self.assertEqual(r["entries"][1]["attributes"], {"prefix": "proc/boot", "uid": "0"})
        self.assertEqual(r["entries"][1]["target"], "proc/boot/b")

    def test_inline_hash_and_escaped_brace(self):
        a = self.parse_bytes(b'"x y" = {\n# raw content\\}\nend\n}\n')
        b = self.parse_bytes(b'"x y" = {\n# changed\\}\nend\n}\n')
        self.assertEqual(a["entries"][0]["line"], 2)
        self.assertNotEqual(a["entries"][0]["content_sha256"], b["entries"][0]["content_sha256"])

    def test_malformed_and_incomplete_never_all_clear(self):
        a = self.parse_bytes(b"include other.build\n")
        d = ifs_review.compare(a, a)
        self.assertFalse(a["complete"])
        self.assertFalse(d["all_clear"])
        self.assertIn("include-not-followed", [d["code"] for d in a["diagnostics"]])

    def test_duplicate_targets(self):
        r = self.parse_bytes(b"a=x\na=y\n")
        self.assertTrue(any(d["code"] == "duplicate-target" for d in r["diagnostics"]))
        self.assertFalse(r["complete"])

    def test_html_injection_escaped(self):
        old = self.parse_bytes(b'"<script>alert(1)</script>"=x\n')
        new = self.parse_bytes(b"")
        page = ifs_review.html_report(ifs_review.compare(old, new))
        self.assertNotIn("<script>alert", page)
        self.assertIn("&lt;script&gt;", page)
        self.assertNotIn("<script", page)

    def test_invalid_encoding_is_visible(self):
        r = self.parse_bytes(b"a=x\n\xff")
        self.assertFalse(r["complete"])
        self.assertTrue(any(d["code"] == "invalid-utf8" for d in r["diagnostics"]))

    def test_input_limit(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "large.build"
            p.write_bytes(b"x" * (ifs_review.MAX_BYTES + 1))
            with self.assertRaises(ifs_review.InputError):
                ifs_review.parse(p)

    def test_changed_source_not_false_unchanged(self):
        old = self.parse_bytes(b"a=old\n")
        new = self.parse_bytes(b"a=new\n")
        d = ifs_review.compare(old, new)
        self.assertEqual([x["target"] for x in d["changed"]], ["proc/boot/a"])
        self.assertFalse(d["all_clear"])

    def test_line_movement_is_not_semantic_change(self):
        old = self.parse_bytes(b"a={\nsame\n}\n")
        new = self.parse_bytes(b"# comment\na={\nsame\n}\n")
        self.assertTrue(ifs_review.compare(old, new)["all_clear"])

    def test_quoted_mapping_and_link(self):
        r = self.parse_bytes(b'[type=link] "my shell" = "bin/ksh"\n')
        self.assertEqual(r["entries"][0]["kind"], "link")
        self.assertEqual(r["entries"][0]["source"], "bin/ksh")

    def test_boolean_script_declaration(self):
        r = self.parse_bytes(b"[+script] boot-script=./boot.script\n")
        self.assertEqual(r["entries"][0]["kind"], "script")

    def test_deterministic_json(self):
        r = self.parse_bytes(b"a=x\n")
        self.assertEqual(ifs_review.dump_json(r), ifs_review.dump_json(r))
        json.loads(ifs_review.dump_json(r))


class CoverageAndWritesTests(unittest.TestCase):
    parse_bytes = ReviewTests.parse_bytes
    def test_implicit_prefix_never_complete(self):
        r = self.parse_bytes(b"a=x\n", explicit_prefix=False)
        self.assertFalse(r["complete"])
        self.assertIn("implicit-prefix", [d["code"] for d in r["diagnostics"]])

    def test_signed_boolean_overrides(self):
        r = self.parse_bytes(b"[+script]\n[-script] a=x\nb=y\n")
        self.assertEqual(r["entries"][0]["kind"], "mapping")
        self.assertEqual(r["entries"][1]["kind"], "script")
        self.assertFalse(r["entries"][0]["attributes"]["script"])

    def test_unknown_attributes_never_complete(self):
        for data in [b"[mystery=foo] a=x\n", b"[?+script] a=x\n", b"[uid=0 uid=1] a=x\n", b"[script] a=x\n"]:
            self.assertFalse(self.parse_bytes(data)["complete"])

    def test_comment_outside_inline_and_quoted_hash(self):
        a = self.parse_bytes(b'[type=link] "a # name" = "source # name" # comment\n')
        self.assertTrue(a["complete"])
        self.assertEqual(a["entries"][0]["source"], "source # name")

    def test_all_inline_escapes(self):
        import hashlib
        r = self.parse_bytes(b"a={\nhello\\q\n}\n")
        self.assertEqual(r["entries"][0]["content_sha256"], hashlib.sha256(b"helloq\n").hexdigest())

    def test_incomplete_inline_close(self):
        self.assertFalse(self.parse_bytes(b"a={\nbody}\n")["complete"])

    def test_unknown_source_type_prevents_false_all_clear(self):
        r = self.parse_bytes(b"tree=./could-be-directory\n")
        self.assertFalse(r["complete"])
        self.assertFalse(ifs_review.compare(r, r)["all_clear"])
        self.assertEqual(r["entries"][0]["kind"], "mapping")
        self.assertIn("source-type-unverified", [d["code"] for d in r["diagnostics"]])

    def test_report_summary_does_not_corrupt_stdout_json(self):
        import contextlib, io
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)/"input.build";p.write_text("[prefix=proc/boot]\na={\nhello\n}\n")
            out,err=io.StringIO(),io.StringIO()
            with contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
                self.assertEqual(ifs_review.main(["inspect",str(p),"--report","--json"]),0)
            self.assertTrue(json.loads(out.getvalue())["complete"])
            self.assertIn("entries;",err.getvalue())

    def test_compare_report_is_useful_and_json_can_be_piped(self):
        import contextlib, io
        with tempfile.TemporaryDirectory() as td:
            old=Path(td)/"old.build";new=Path(td)/"new.build"
            old.write_text("[prefix=proc/boot]\na={\nold\n}\n")
            new.write_text("[prefix=proc/boot]\na={\nnew\n}\n")
            out,err=io.StringIO(),io.StringIO()
            with contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
                self.assertEqual(ifs_review.main(["compare",str(old),str(new),"--report","--json"]),0)
            self.assertEqual(len(json.loads(out.getvalue())["changed"]),1)
            self.assertIn("1 changed",err.getvalue())

    def test_html_stdout_is_not_corrupted_by_summary(self):
        import contextlib, io
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"input.build";p.write_text("[prefix=]\na={\nhello\n}\n")
            out,err=io.StringIO(),io.StringIO()
            with contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
                self.assertEqual(ifs_review.main(["compare",str(p),str(p),"--html","-","--report"]),0)
            self.assertTrue(out.getvalue().startswith("<!doctype html>"))
            self.assertIn("0 changed",err.getvalue())

    def test_unsafe_prefix_requires_manual_review_and_empty_is_valid(self):
        for prefix in ['a/*','a/?','a/[0]']:
            r=self.parse_bytes(('[prefix="'+prefix+'" type=link] sh=ksh\n').encode())
            self.assertFalse(r["complete"])
            self.assertIn("prefix-not-resolved",[d["code"] for d in r["diagnostics"]])
        good=self.parse_bytes(b"[prefix= type=link] sh=ksh\n")
        self.assertTrue(good["complete"])
        self.assertEqual(good["entries"][0]["target"],"sh")

    def test_empty_not_all_clear(self):
        r = self.parse_bytes(b"")
        self.assertFalse(ifs_review.compare(r, r)["all_clear"])

    def test_duplicate_output_and_input_are_never_overwritten(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "input.build"
            original = b"[prefix=proc/boot]\na=x\n";p.write_bytes(original)
            self.assertEqual(ifs_review.main(["inspect", str(p), "--json", str(p)]), 2)
            self.assertEqual(p.read_bytes(), original)
            out=Path(td)/"report"
            self.assertEqual(ifs_review.main(["compare", str(p), str(p), "--json", str(out), "--html", str(out)]), 2)
            self.assertFalse(out.exists())
            out.write_text("keep")
            self.assertEqual(ifs_review.main(["inspect", str(p), "--json", str(out)]), 2)
            self.assertEqual(out.read_text(), "keep")


if __name__ == "__main__":
    unittest.main()
