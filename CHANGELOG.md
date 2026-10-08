cat > CHANGELOG.md << 'EOF'
# Changelog

All notable changes to MBPRBF are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-10-08

### Added

- PE builder for Windows x64 — DOS, COFF, Optional Header, Sections,
  `.rsrc`, `.pdata`, `.xdata`, `.reloc`.
- Import Address Table — automatic DLL/function registration.
- Resource builder — icons, manifest, version info (`VS_VERSIONINFO`).
- Method system — Microsoft x64 ABI: `RCX`/`RDX`/`R8`/`R9` + `XMM0-3` + stack.
- Real x64 SEH — `.pdata`/`.xdata`/`UNWIND_INFO`/`ScopeTable`.
- FFI — C/Rust DLL interop.
- Arrays — static/dynamic, homogeneous/heterogeneous.
- Compile-time memory safety — leak / double-free / use-after-free.
- GUI — Window, Label, Button, TextArea, CheckBox, RadioButton,
  GroupBox, ListBox, ComboBox, ProgressBar, TrackBar, Timer.
- GDI — Rect, Square, Circle, Ellipse, Polygon, Line, Text, Image.
- Console / GUI / GDI builders.

### Records

- `hello.exe` — 3584 bytes, no `.reloc`, `DYNAMIC_BASE` on.

### License

- GPL-3.0-or-later.

[1.0.0]: https://github.com/madmenbuilder/mbprbf/releases/tag/v1.0.0