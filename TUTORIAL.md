# Tutorial: review a synthetic buildfile change

1. Inventory the original: `python3 ifs_review.py inspect examples/before.build --report --json before.json`.
2. Compare revisions: `python3 ifs_review.py compare examples/before.build examples/after.build --json changes.json --html changes.html`.
3. Open `changes.html` locally. Review every added, removed, and changed target plus both diagnostic lists.
4. If `complete` is false, resolve or manually review every diagnostic. Do not interpret an incomplete empty diff as an all-clear.
5. Use the licensed QNX SDP 8.0 toolchain to perform the real build, followed by target-specific boot/runtime testing.

The examples are original synthetic text. The changed startup source, renamed link, changed inline-body hash, and new manifest demonstrate the review categories without containing or reading any real host source.

The supplied file mappings intentionally generate `source-type-unverified` diagnostics. A directory source need not end in `/`, so this offline tool refuses to assert those source types. It never follows `./synthetic/...`. A complete inventory is possible for supported inline and link declarations, but still is not build or boot evidence. Use `compare ... --report` for a concise terminal view.
