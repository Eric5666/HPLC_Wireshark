#!/usr/bin/env python3
"""Patch update.json with a release's version and package download URLs.

The built-in updater (src/updater/Updater.cpp + Downloader.cpp) reads, for the
running platform key ("windows" / "linux" / ...), the object

    updates.<platform>.{latest-version, download-url, changelog,
                        mandatory-update}

It does NOT verify package SHA-256. Checksums are published separately as the
release asset SHA256SUMS.txt (see .github/workflows/build.yml) for users to
verify by hand. A stale "sha256" key left in the manifest is removed here.

Usage:
    update_json_release.py [--manifest update.json] [--out update.json]
                           [--version 2.0.2] [--base-url URL]
                           PLATFORM=PATH [PLATFORM=PATH ...]

    PLATFORM is the manifest key (windows, linux, ...); PATH is the package
    file. With --base-url, download-url becomes <base-url>/<basename(PATH)>;
    without it the existing download-url must already end with the package
    file name (guards against pointing the manifest at a different file).
    --version sets latest-version. Platforms not named are left untouched.

Only the standard library is used (runs on any CI runner / dev box).
"""
import argparse
import json
import os
import sys


def patch(manifest, packages, version=None, base_url=None):
    """packages: list of (platform, path). Returns list of package names."""
    updates = manifest.setdefault("updates", {})
    if not isinstance(updates, dict):
        raise ValueError("manifest 'updates' is not an object")
    names = []
    for platform, path in packages:
        if not os.path.isfile(path):
            raise FileNotFoundError(f"{platform}: package not found: {path}")
        name = os.path.basename(path)
        entry = updates.setdefault(platform, {})
        if base_url:
            entry["download-url"] = base_url.rstrip("/") + "/" + name
        else:
            url = entry.get("download-url", "")
            if url.rsplit("/", 1)[-1] != name:
                raise ValueError(
                    f"{platform}: download-url {url!r} does not point at {name!r};"
                    " pass --base-url to rewrite it")
        if version:
            entry["latest-version"] = version
        entry.pop("sha256", None)   # no longer used by the updater
        names.append(name)
    return names


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--manifest", default="update.json")
    ap.add_argument("--out", help="output path (default: overwrite --manifest)")
    ap.add_argument("--version", help="set latest-version")
    ap.add_argument("--base-url", help="rewrite download-url as BASE/<file name>")
    ap.add_argument("packages", nargs="+", metavar="PLATFORM=PATH")
    args = ap.parse_args(argv)

    packages = []
    for spec in args.packages:
        platform, sep, path = spec.partition("=")
        if not sep or not platform or not path:
            ap.error(f"bad package spec {spec!r}, expected PLATFORM=PATH")
        packages.append((platform, path))

    with open(args.manifest, encoding="utf-8") as f:
        manifest = json.load(f)
    try:
        names = patch(manifest, packages, args.version, args.base_url)
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    out = args.out or args.manifest
    with open(out, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
        f.write("\n")
    for name in names:
        print(name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
