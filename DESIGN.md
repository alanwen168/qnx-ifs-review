# IFS Review — QNX 8.0 buildfile change review on a Linux host

Original contest project, started 2026-11-16. A local-only developer tool that parses QNX mkifs buildfile declarations into a source-linked inventory and compares revisions. It helps reviewers spot target-file changes and attribute-scope changes before using their licensed QNX build tools. It does not execute inputs, invoke a compiler, create an IFS image, validate a board, or claim a boot/runtime result.

Deliverable: dependency-free Python 3.11+ CLI, deterministic JSON, a self-contained escaped HTML review report, meaningful tests and two original synthetic QNX-format buildfile revisions. No production code, personal data, QNX binaries or copied BSP files.

QNX-specific behavior: bracket attributes persist only on attribute-only lines; attributes on a file declaration apply only there. Preserve inline file bodies, including hashes (mkifs does not treat an inline hash as a comment), and track source lines. Resolve a known prefix conservatively, respect boolean script/type=link declarations, show symbolic source paths without expanding host environment variables. Differences must include target, attributes, source mapping and inline content hashes. Unsupported expressions, include directives, directory expansion, conditional or ambiguous attributes and unresolved expansions must produce explicit incomplete coverage and diagnostics; never emit an all-clear for partial analysis. Unknown inputs are reported, never silently discarded. Escape all strings in HTML, no network or scripts. Inputs size bounded; deterministic no timestamps/absolute host paths in output. Read text only and write only explicitly requested reports. Never follow buildfile sources/includes or execute shell directives.

Official references, read 2026-11-16:
- https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.building/topic/buildfiles/buildfile_syntax.html
- https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.utilities/topic/m/mkifs.html
- https://qnx.devpost.com/rules

The official mkifs grammar is broader than a static declaration inventory. Completeness is scoped to supported parsing only; successful review is not evidence mkifs accepts the file. A user must still build and test using the correct licensed QNX SDP 8.0 toolchain and target. Host-based developer tooling and QNX-specific analysis qualify under the contest rules; category Developer Tooling & Host Tools.
