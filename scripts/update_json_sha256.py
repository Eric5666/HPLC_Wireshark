#!/usr/bin/env python3
"""Patch update.json with the release packages' SHA-256 (and URL / version).

The built-in updater (src/updater/Updater.cpp + Downloader.cpp) reads, for the
running platform key ("windows" / "linux" / ...), the object

    updates.<platform>.{latest-version, download-url, sha256, changelog,
                        mandatory-update}

and REFUSES to open a downloaded package unless "sha256" is present, is 64
lowercase hex chars and matches the file. This script fills those fields from
the real release artifacts so the manifest can never drift from the assets.

Usage:
    update_json_sha256.py [--manifest update.json] [--out update.json]
                          [--version 2.0.2] [--base-url URL]
                          [--sums SHA256SUMS.txt]
                          PLATFORM=PATH [PLATFORM=PATH ...]

    PLATFORM is the manifest key (windows, linux, ...); PATH is the package
    file. With --base-url, download-url becomes <base-url>/<basename(PATH)>;
    without it the existing download-url must already end with the package
    file name (guards against hashing one file while pointing at another).
    --version sets latest-version. Platforms not named are left untouched.
    --sums additionally writes a sha256sum-compatible list.

Only the standard library is used (runs on any CI runner / dev box).
"""
import argparse
import hashlib
import json
import os
import sys


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def patch(manifest, packages, version=None, base_url=None):
    """packages: list of (platform, path). Returns list of (name, digest)."""
    updates = manifest.setdefault("updates", {})
    if not isinstance(updates, dict):
        raise ValueError("manifest 'updates' is not an object")
    sums = []
    for platform, path in packages:
        if not os.path.isfile(path):
            raise FileNotFoundError(f"{platform}: package not found: {path}")
        name = os.path.basename(path)
        digest = sha256_file(path)
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
        entry["sha256"] = digest
        sums.append((name, digest))
    return sums


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--manifest", default="update.json")
    ap.add_argument("--out", help="output path (default: overwrite --manifest)")
    ap.add_argument("--version", help="set latest-version")
    ap.add_argument("--base-url", help="rewrite download-url as BASE/<file name>")
    ap.add_argument("--sums", help="also write a sha256sum-style list here")
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
        sums = patch(manifest, packages, args.version, args.base_url)
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    out = args.out or args.manifest
    with open(out, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
        f.write("\n")
    if args.sums:
        with open(args.sums, "w", encoding="utf-8") as f:
            for name, digest in sums:
                f.write(f"{digest}  {name}\n")
    for name, digest in sums:
        print(f"{digest}  {name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
