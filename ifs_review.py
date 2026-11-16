#!/usr/bin/env python3
"""Conservative, dependency-free QNX 8 mkifs buildfile inventory reviewer."""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
import shlex
import sys
from pathlib import Path

MAX_BYTES = 2 * 1024 * 1024
MAX_LINES = 50_000
MAX_ENTRIES = 10_000
VERSION = 1


class InputError(Exception):
    pass


def diagnostic(line: int, code: str, message: str) -> dict:
    return {"line": line, "code": code, "message": message}


# This inventory understands only attributes whose declaration-level effects are documented.
VALUE_ATTRIBUTES = {"uid", "gid", "perms", "dperms", "prefix", "mount", "type", "search", "virtual", "sha256", "sha512"}
BOOLEAN_ATTRIBUTES = {"script", "compress", "optional", "raw", "followlink", "autolink", "keeplinked"}


def attrs(text: str, line: int, diags: list[dict]) -> dict[str, str | bool]:
    try:
        words = shlex.split(text, posix=True)
    except ValueError as exc:
        diags.append(diagnostic(line, "malformed-attributes", str(exc)))
        return {}
    out: dict[str, str | bool] = {}
    for word in words:
        if any(c in word for c in "$`()"):
            diags.append(diagnostic(line, "dynamic-attribute", f"attribute is not statically resolved: {word}"))
        if word.startswith("?"):
            diags.append(diagnostic(line, "conditional-attribute", f"conditional attribute is not resolved: {word}"))
        if "=" in word:
            key, value = word.split("=", 1)
            if key not in VALUE_ATTRIBUTES:
                diags.append(diagnostic(line, "unsupported-attribute", f"attribute is retained but not interpreted: {word}"))
            if key == "type" and value not in {"file", "link"}:
                diags.append(diagnostic(line, "unsupported-file-type", f"type is retained but not expanded: {value}"))
            if key in out:
                diags.append(diagnostic(line, "ambiguous-attribute", f"repeated attribute: {key}"))
            out[key] = value
        elif word.startswith(("+", "-")) and word[1:] in BOOLEAN_ATTRIBUTES:
            key = word[1:]
            value = word.startswith("+")
            if key in out:
                diags.append(diagnostic(line, "ambiguous-attribute", f"repeated attribute: {key}"))
            out[key] = value
        else:
            diags.append(diagnostic(line, "unsupported-attribute", f"expected a known signed boolean or key=value: {word}"))
            out[word] = True
    return out


def split_decl(text: str, line: int, diags: list[dict]) -> tuple[str, str] | None:
    """Split one explicit target=source declaration, respecting quotes."""
    quote = None
    escaped = False
    positions = []
    for i, ch in enumerate(text):
        if escaped:
            escaped = False
        elif ch == "\\":
            escaped = True
        elif quote:
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
        elif ch == "=":
            positions.append(i)
    if quote:
        diags.append(diagnostic(line, "malformed-declaration", "unterminated quote"))
        return None
    if len(positions) != 1:
        diags.append(diagnostic(line, "unsupported-declaration", "expected one explicit target=source mapping"))
        return None
    left, right = text[:positions[0]].strip(), text[positions[0] + 1:].strip()
    try:
        lparts, rparts = shlex.split(left), shlex.split(right)
    except ValueError as exc:
        diags.append(diagnostic(line, "malformed-declaration", str(exc)))
        return None
    if len(lparts) != 1 or len(rparts) != 1:
        diags.append(diagnostic(line, "unsupported-declaration", "mapping sides must each be one quoted or unquoted token"))
        return None
    return lparts[0], rparts[0]


def unsafe(value: str) -> bool:
    return any(x in value for x in ("$", "`", "$(", "${", "*", "?", "["))


def target_with_prefix(target: str, active: dict) -> str:
    # Keep identity unambiguous without pretending to resolve mkifs' boot-dependent default.
    prefix = active.get("prefix")
    if not isinstance(prefix, str) or unsafe(prefix):
        return target
    if not prefix:
        return target
    return prefix.rstrip("/") + "/" + target.lstrip("/")


def unescape_inline(raw: str) -> str:
    # mkifs inline escapes relevant to static content; retain unknown escapes.
    return re.sub(r"\\([\s\S])", r"\1", raw)


def parse(path: Path) -> dict:
    with path.open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise InputError(f"input exceeds {MAX_BYTES} bytes")
    invalid = False
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("utf-8", errors="replace")
        invalid = True
    lines = text.splitlines(keepends=True)
    if len(lines) > MAX_LINES:
        raise InputError(f"input exceeds {MAX_LINES} lines")
    diags: list[dict] = []
    if invalid:
        diags.append(diagnostic(1, "invalid-utf8", "invalid UTF-8 was replaced; coverage is incomplete"))
    persistent: dict[str, str | bool] = {}
    entries: list[dict] = []
    i = 0
    while i < len(lines):
        raw = lines[i]
        lineno = i + 1
        stripped = raw.strip()
        i += 1
        if not stripped or stripped.startswith("#"):
            continue
        # Comments outside inline bodies: only whitespace-preceded, unquoted hashes.
        quoted = False
        escaped = False
        for pos, ch in enumerate(stripped):
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                quoted = not quoted
            elif ch == "#" and not quoted and (pos == 0 or stripped[pos-1].isspace()):
                stripped = stripped[:pos].rstrip()
                break
        if not stripped:
            continue
        if raw.rstrip("\n\r").endswith("\\"):
            diags.append(diagnostic(lineno, "continuation-unsupported", "outer line continuations are not expanded"))
        if "\\" in stripped:
            diags.append(diagnostic(lineno, "outer-escape-unsupported", "outer escapes are retained for review but not resolved as mkifs"))
        if "\x00" in raw:
            diags.append(diagnostic(lineno, "nul-byte", "NUL byte in buildfile"))
        if stripped.startswith(("include ", ".include ")):
            diags.append(diagnostic(lineno, "include-not-followed", "include directives are not followed"))
            continue
        if stripped.startswith(("if ", "ifdef ", "ifndef ", "else", "endif")):
            diags.append(diagnostic(lineno, "conditional-unsupported", "conditional syntax is not evaluated"))
            continue
        local: dict[str, str | bool] = {}
        rest = stripped
        if rest.startswith("["):
            end = -1
            quoted = False
            escaped = False
            for pos, ch in enumerate(rest[1:], 1):
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == '"':
                    quoted = not quoted
                elif ch == "]" and not quoted:
                    end = pos
                    break
            if end < 0:
                diags.append(diagnostic(lineno, "malformed-attributes", "missing closing bracket"))
                continue
            local = attrs(rest[1:end], lineno, diags)
            rest = rest[end + 1:].strip()
            if rest.startswith("["):
                diags.append(diagnostic(lineno, "multiple-attribute-groups", "only one combined bracket group is supported"))
                continue
            if not rest:
                persistent.update(local)
                continue
        effective = dict(persistent)
        effective.update(local)  # per-file attributes do not leak
        if "prefix" not in effective:
            diags.append(diagnostic(lineno, "implicit-prefix", "mkifs prefix depends on image type; specify prefix explicitly for resolved inventory"))
        if "prefix" in effective and (not isinstance(effective["prefix"], str) or unsafe(effective["prefix"])):
            diags.append(diagnostic(lineno, "prefix-not-resolved", "prefix contains unsupported expansion or syntax"))
        if effective.get("mount", "/") != "/":
            diags.append(diagnostic(lineno, "mount-not-resolved", "non-default mount is retained; target is an image-relative declaration"))
        inline_match = re.match(r"^(.*?)\s*=\s*\{\s*$", rest)
        if inline_match:
            try:
                names = shlex.split(inline_match.group(1).strip())
            except ValueError as exc:
                diags.append(diagnostic(lineno, "malformed-inline", str(exc)))
                continue
            if len(names) != 1:
                diags.append(diagnostic(lineno, "malformed-inline", "inline target must be one token"))
                continue
            body_parts: list[str] = []
            closed = False
            while i < len(lines):
                body_line = lines[i]
                body_lineno = i + 1
                i += 1
                escaped = False
                close_at = None
                for n, ch in enumerate(body_line):
                    if escaped:
                        escaped = False
                    elif ch == "\\":
                        escaped = True
                    elif ch == "}":
                        close_at = n
                        break
                if close_at is not None:
                    if body_line[:close_at].strip():
                        diags.append(diagnostic(body_lineno, "inline-close-not-alone", "inline contents must not share the closing brace line"))
                    body_parts.append(body_line[:close_at])
                    if body_line[close_at + 1:].strip():
                        diags.append(diagnostic(body_lineno, "trailing-inline-text", "text after inline terminator is unsupported"))
                    closed = True
                    break
                body_parts.append(body_line)
            if not closed:
                diags.append(diagnostic(lineno, "unterminated-inline", "inline body has no unescaped closing brace"))
                continue
            content = unescape_inline("".join(body_parts))
            entries.append({"target": target_with_prefix(names[0], effective), "declared_target": names[0],
                            "kind": "script" if effective.get("script") is True else "inline", "source": None, "attributes": effective,
                            "raw_declaration": stripped, "content_sha256": hashlib.sha256(content.encode()).hexdigest(),
                            "content_bytes": len(content.encode()), "line": lineno})
        else:
            mapping = split_decl(rest, lineno, diags)
            if mapping is None:
                continue
            target, source = mapping
            if source.endswith("/"):
                diags.append(diagnostic(lineno, "directory-expansion", "directory source contents are not expanded"))
            if unsafe(target) or unsafe(source):
                diags.append(diagnostic(lineno, "dynamic-or-expanding-path", "path expansion is not resolved or followed"))
            if effective.get("type") != "link":
                diags.append(diagnostic(lineno, "source-type-unverified", "mapped source is not inspected; it may be a file or directory and its contents are not checked"))
            if effective.get("type") == "link":
                kind = "link"
            elif effective.get("script") is True:
                kind = "script"
            else:
                kind = "mapping"
            entries.append({"target": target_with_prefix(target, effective), "declared_target": target,
                            "kind": kind, "source": source, "attributes": effective,
                            "raw_declaration": stripped, "content_sha256": None, "content_bytes": None, "line": lineno})
        if len(entries) > MAX_ENTRIES:
            raise InputError(f"input exceeds {MAX_ENTRIES} entries")
    if not entries:
        diags.append(diagnostic(1, "no-declarations", "no supported file declarations were analyzed"))
    seen: dict[str, int] = {}
    for entry in entries:
        target = entry["target"]
        if target in seen:
            diags.append(diagnostic(entry["line"], "duplicate-target", f"target also declared on line {seen[target]}: {target}"))
        else:
            seen[target] = entry["line"]
    diags.sort(key=lambda d: (d["line"], d["code"], d["message"]))
    return {"schema_version": VERSION, "file": path.name, "complete": not diags,
            "entries": entries, "diagnostics": diags,
            "disclaimer": "Static supported-syntax inventory only; not full mkifs validation or boot evidence."}


def identity_map(entries: list[dict]) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for e in entries:
        out.setdefault(e["target"], []).append(e)
    return out


def compare(old: dict, new: dict) -> dict:
    a, b = identity_map(old["entries"]), identity_map(new["entries"])
    added, removed, changed, unchanged = [], [], [], []
    for target in sorted(set(a) | set(b)):
        if target not in a:
            added.append({"target": target, "new": b[target]})
        elif target not in b:
            removed.append({"target": target, "old": a[target]})
        elif [{k: v for k, v in e.items() if k not in {"line", "raw_declaration"}} for e in a[target]] != [{k: v for k, v in e.items() if k not in {"line", "raw_declaration"}} for e in b[target]]:
            changed.append({"target": target, "old": a[target], "new": b[target]})
        else:
            unchanged.append(target)
    complete = old["complete"] and new["complete"]
    return {"schema_version": VERSION, "old_file": old["file"], "new_file": new["file"],
            "complete": complete, "all_clear": complete and not (added or removed or changed),
            "added": added, "removed": removed, "changed": changed, "unchanged": unchanged,
            "old_diagnostics": old["diagnostics"], "new_diagnostics": new["diagnostics"],
            "disclaimer": "Declaration comparison only: mapped file contents, SDK availability, image generation and boot behavior are not checked. Licensed QNX build and target testing remain required."}


def dump_json(value: dict) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"


def html_report(diff: dict) -> str:
    def esc(value: object) -> str:
        return html.escape(str(value), quote=True)

    def describe(entries: list[dict]) -> str:
        if not entries:
            return '<span class="muted">Absent</span>'
        parts = []
        for entry in entries:
            source = entry["source"] or "inline content"
            digest = entry.get("content_sha256")
            attrs_text = ", ".join(f"{k}={v}" for k, v in sorted(entry["attributes"].items()))
            parts.append(f"<p><code>{esc(source)}</code><br><span class=muted>Line {esc(entry['line'])} · {esc(entry['kind'])}</span><br>{esc(attrs_text)}" +
                         (f"<br><code title='{esc(digest)}'>SHA-256 {esc(digest[:16])}…</code>" if digest else "") + "</p>")
        return "".join(parts)

    status = "No declaration changes" if diff["all_clear"] else ("Incomplete coverage — manual review needed" if not diff["complete"] else "Declaration changes found")
    rows = []
    for label in ("added", "removed", "changed"):
        for item in diff[label]:
            detail = esc(json.dumps(item, ensure_ascii=False, sort_keys=True, indent=2))
            rows.append(f"<tr><td><span class='pill {label}'>{esc(label)}</span><br><code>{esc(item['target'])}</code><details><summary>Full record</summary><pre>{detail}</pre></details></td><td>{describe(item.get('old', []))}</td><td>{describe(item.get('new', []))}</td></tr>")
    if not rows:
        rows.append("<tr><td colspan=3>No differences found in the analyzed declarations. See coverage and diagnostics below.</td></tr>")
    diagnostics = esc(json.dumps({"old": diff["old_diagnostics"], "new": diff["new_diagnostics"]}, ensure_ascii=False, sort_keys=True, indent=2))
    cards = "".join(f"<div class=card><strong>{len(diff[k])}</strong><span>{k.title()}</span></div>" for k in ("added", "removed", "changed", "unchanged"))
    return ("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=viewport content=\"width=device-width,initial-scale=1\"><title>IFS Review — buildfile comparison</title>"
            "<style>body{font:15px/1.6 system-ui;margin:0;background:#f4f6fa;color:#182436}main{max-width:1200px;margin:auto;padding:36px 24px}h1{font-size:36px;letter-spacing:-1px;margin:8px 0}.eyebrow{color:#41668e;letter-spacing:2px;font-size:12px;font-weight:700}.subtitle,.muted{color:#586a80}.status{background:#fff4d7;border-left:4px solid #bf841e;padding:12px 16px}.cards{display:flex;gap:12px;margin:24px 0}.card{flex:1;background:white;padding:16px;border:1px solid #d9e0e9;border-radius:8px}.card strong{display:block;font-size:28px}.card span{color:#586a80}table{border-collapse:collapse;width:100%;background:white}td,th{border:1px solid #d9e0e9;padding:14px;vertical-align:top;text-align:left}th{background:#eaf0f7}pre,code{overflow-wrap:anywhere;white-space:pre-wrap;font-family:ui-monospace,monospace}pre{font-size:12px;max-width:420px}details{margin-top:12px}summary{cursor:pointer;color:#41668e}.pill{font-size:11px;text-transform:uppercase;border-radius:4px;padding:3px 6px;display:inline-block;margin-bottom:8px}.added{background:#d9f0e6}.removed{background:#fde2df}.changed{background:#fff0c6}.scroll{overflow-x:auto}footer{font-size:13px;margin-top:24px;color:#586a80}</style>"
            f"</head><body><main><div class=eyebrow>QNX 8.0 · HOST DEVELOPER TOOL</div><h1>IFS Review</h1><p class=subtitle>Source-linked buildfile declaration comparison</p><p class=status>{esc(status)}</p>"
            f"<p>Before: <code>{esc(diff['old_file'])}</code> → After: <code>{esc(diff['new_file'])}</code></p><div class=cards>{cards}</div>"
            "<div class=scroll><table><thead><tr><th>Target / change</th><th>Before</th><th>After</th></tr></thead><tbody>" + "".join(rows) +
            f"</tbody></table></div><h2>Coverage diagnostics</h2><pre>{diagnostics}</pre><footer>{esc(diff['disclaimer'])} No scripts, source-file access or network requests are performed by this report.</footer></main></body></html>\n")


def write_output(content: str, destination: str | None) -> None:
    if destination in (None, "-"):
        sys.stdout.write(content)
    else:
        with Path(destination).open("x", encoding="utf-8") as stream:
            stream.write(content)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="command", required=True)
    ins = sub.add_parser("inspect", help="inventory one buildfile")
    ins.add_argument("file", type=Path)
    ins.add_argument("--json", nargs="?", const="-", metavar="FILE")
    ins.add_argument("--report", action="store_true", help="print a concise text summary")
    cmp = sub.add_parser("compare", help="compare two buildfiles")
    cmp.add_argument("old", type=Path); cmp.add_argument("new", type=Path)
    cmp.add_argument("--json", nargs="?", const="-", metavar="FILE")
    cmp.add_argument("--html", metavar="FILE")
    cmp.add_argument("--report", action="store_true", help="print declaration-change counts and coverage diagnostics")
    args = ap.parse_args(argv)
    try:
        inputs = [args.file] if args.command == "inspect" else [args.old, args.new]
        outputs = [getattr(args, key, None) for key in ("json", "html")]
        destinations = [Path(o).resolve() for o in outputs if o not in (None, "-")]
        if len(destinations) != len(set(destinations)):
            raise InputError("report output paths must be distinct")
        if sum(o == "-" for o in outputs) > 1:
            raise InputError("only one report may use stdout")
        for path in inputs:
            if not path.is_file():
                raise InputError("input must be a regular file")
        for destination in destinations:
            if destination in [path.resolve() for path in inputs] or destination.exists():
                raise InputError("reports must use new paths and cannot overwrite inputs")
        if args.command == "inspect":
            result = parse(args.file)
            if args.report:
                summary_stream = sys.stderr if args.json == "-" or getattr(args, "html", None) == "-" else sys.stdout
                print(f"{result['file']}: {len(result['entries'])} entries; complete={str(result['complete']).lower()}; diagnostics={len(result['diagnostics'])}", file=summary_stream)
            if args.json is not None or not args.report:
                write_output(dump_json(result), args.json)
        else:
            result = compare(parse(args.old), parse(args.new))
            if args.report:
                summary_stream = sys.stderr if args.json == "-" or getattr(args, "html", None) == "-" else sys.stdout
                counts = ", ".join(f"{len(result[k])} {k}" for k in ("added", "removed", "changed", "unchanged"))
                print(f"{result['old_file']} -> {result['new_file']}: {counts}; complete={str(result['complete']).lower()}", file=summary_stream)
                for label in ("old", "new"):
                    for item in result[label + "_diagnostics"]:
                        print(f"  {label}:{item['line']} {item['code']}: {item['message']}", file=summary_stream)
            if args.html:
                write_output(html_report(result), args.html)
            if args.json is not None or not (args.html or args.report):
                write_output(dump_json(result), args.json)
        return 0
    except (OSError, InputError) as exc:
        print(f"ifs_review: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
