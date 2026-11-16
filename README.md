# IFS Review

IFS Review is a dependency-free Python 3.11+ host tool for a conservative, source-linked review of selected QNX SDP 8.0 `mkifs` buildfile declarations. It inventories explicit `target=source`, `type=link`, persistent and per-file attributes, and multiline inline files; then compares targets, mappings, attributes, and inline-content hashes.

It is a preflight aid, not a `mkifs` compiler or validator. It does not execute input, expand environment variables, follow sources or includes, create an IFS, or establish that an image builds or boots. Always build and test with the correct licensed QNX SDP 8.0 tools and target. This repository redistributes no QNX binaries, licensed content, or documentation.

## Use

```sh
python3 ifs_review.py inspect examples/before.build --json inventory.json
python3 ifs_review.py inspect examples/before.build --report
python3 ifs_review.py compare examples/before.build examples/after.build --report
python3 ifs_review.py compare examples/before.build examples/after.build --json diff.json --html review.html
```

Omit an output filename (for example, `--json`) to write JSON to stdout. Output is deterministic and uses only input basenames. HTML is self-contained, escaped, and contains no JavaScript or network resources.

Supported syntax is deliberately narrow: one bracket group at the start of a line; attribute-only groups persist, while a group on a declaration applies only to that declaration; explicit one-token mappings (quoted tokens allowed); and `name = {` inline bodies ending at an unescaped `}`. A statically explicit `prefix` is required to resolve inventory identity; without it coverage is incomplete because the mkifs default depends on whether the image is bootable. Inline backslash escapes are unescaped for hashing as documented by mkifs.

Includes, conditionals, directory/glob expansion, dynamic paths, malformed/ambiguous syntax, invalid UTF-8, and duplicates are diagnosed and make `complete` false. They are never silently treated as an all-clear. Parsing success is still not proof that full `mkifs` accepts the file.

Run tests with `python3 -m unittest -v`.

## References

- https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.building/topic/buildfiles/buildfile_syntax.html
- https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.utilities/topic/m/mkifs.html
- https://qnx.devpost.com/rules

Reports must use new paths; the CLI refuses overwriting inputs or existing report files. Comparisons cover declarations and inline contents only: mapped host files are never read or hashed. Complete coverage means only that the declaration subset was parsed, not that QNX accepts, compiles, or boots it. Directory expansion, unknown attributes, ambiguous defaults and outer escape syntax require manual review.

Mapped sources are always marked `source-type-unverified`, since a source without a trailing slash can still be a directory in mkifs. Their kind is `mapping`, not an asserted regular file. The declaration diff remains useful, but coverage stays incomplete until a human verifies those sources using the licensed build environment. Pure supported inline/link inventories can have complete declaration coverage. With `inspect --report --json`, the summary goes to stderr and stdout remains parseable JSON.
