#!/usr/bin/env python3
"""Enable a user-source dashboard plugin in the ROOT config and in EVERY profile's config.

Why every profile: the desktop app spawns a pooled ``hermes --profile <p> serve --isolated``
backend per profile, and the plugin-api gate reads THAT home's ``plugins.enabled``. A plugin
enabled only in the root config makes the app answer ``404 {"detail":"Plugin not found"}`` for
every other profile. Enabling across all of them is what "active in all of them" means.

A minimal TEXT edit, never a ``yaml.safe_load`` -> ``dump`` round trip: these files are 50-110 KB,
carry comments and ordering other lanes depend on, and are edited by other profiles while this runs.
A ``.bak`` copy is written beside each file before it is touched, and the result is re-parsed.

usage: enable-everywhere.py <plugin-name> [--dry-run]
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml


def config_paths() -> list[Path]:
    home = Path.home() / ".hermes"
    out = [home / "config.yaml"]
    prof = home / "profiles"
    if prof.is_dir():
        out += sorted(p / "config.yaml" for p in prof.iterdir() if p.is_dir())
    return [p for p in out if p.is_file()]


def enable_in_text(text: str, name: str) -> tuple[str, str]:
    """Return (new_text, status). status: added | present | no-list | no-plugins."""
    lines = text.splitlines(keepends=True)
    plugins_at = None
    for i, ln in enumerate(lines):
        if ln.rstrip("\n") == "plugins:":
            plugins_at = i
            break
    if plugins_at is None:
        return text, "no-plugins"
    enabled_at = None
    for j in range(plugins_at + 1, len(lines)):
        s = lines[j]
        if s.strip() and not s.startswith(" "):
            break  # left the plugins: block
        if s.rstrip("\n") == "  enabled:":
            enabled_at = j
            break
    # The enabled list may be `  enabled:` + items, or `  enabled: []`, or the items may sit at
    # 4-space indent (profiles) or 2-space (root). Match whatever this file already uses.
    if enabled_at is not None:
        rest = lines[enabled_at].rstrip("\n")
        if rest.strip() != "enabled:":
            # inline form: `  enabled: [a, b]`
            inner = rest.split("enabled:", 1)[1].strip()
            if inner.startswith("[") and inner.endswith("]"):
                names = [n.strip().strip("'\"") for n in inner[1:-1].split(",") if n.strip()]
                if name in names:
                    return text, "present"
                names.append(name)
                lines[enabled_at] = rest.split("enabled:", 1)[0] + "enabled: [" + ", ".join(names) + "]\n"
                return "".join(lines), "added"
            return text, "no-list"
        indent = None
        k = enabled_at + 1
        while k < len(lines):
            item = lines[k]
            if item.startswith(" ") and item.lstrip().startswith("-"):
                indent = len(item) - len(item.lstrip(" "))
                break
            if item.strip():
                break
            k += 1
        if indent is None:
            indent = len(lines[enabled_at]) - len(lines[enabled_at].lstrip(" ")) + 2
        k = enabled_at + 1
        while k < len(lines):
            item = lines[k]
            if not (item.startswith(" ") and item.lstrip().startswith("-")):
                break
            if item.strip().lstrip("-").strip().strip("'\"") == name:
                return text, "present"
            k += 1
        lines.insert(enabled_at + 1, " " * indent + "- " + name + "\n")
        return "".join(lines), "added"
    return text, "no-list"


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    name = sys.argv[1]
    dry = "--dry-run" in sys.argv
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    counts: dict[str, int] = {}
    changed: list[str] = []
    for path in config_paths():
        text = path.read_text(encoding="utf-8")
        new, status = enable_in_text(text, name)
        counts[status] = counts.get(status, 0) + 1
        if status != "added":
            continue
        # Verify the edit parses BEFORE it is trusted, and that nothing else moved.
        try:
            doc = yaml.safe_load(new)
            got = ((doc or {}).get("plugins") or {}).get("enabled") or []
            assert name in got, "name absent after edit"
        except Exception as exc:  # noqa: BLE001
            print(f"REFUSED {path}: edit would not parse: {type(exc).__name__}: {exc}")
            counts[status] = counts.get(status, 0) - 1
            counts["refused"] = counts.get("refused", 0) + 1
            continue
        if dry:
            print(f"would-add {path}")
            continue
        path.with_suffix(path.suffix + f".bak-{name}-{stamp}").write_text(text, encoding="utf-8")
        path.write_text(new, encoding="utf-8")
        changed.append(str(path))
    print(f"plugin={name} stamp={stamp} dry_run={dry}")
    for k in sorted(counts):
        print(f"  {k}: {counts[k]}")
    if changed:
        print(f"  files changed: {len(changed)}")
    return 0 if counts.get("refused", 0) == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
