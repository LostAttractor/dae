#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Generate or verify the Go parser using the pinned ANTLR compiler."""

import argparse
import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile
from urllib.request import urlopen


ROOT = Path(__file__).resolve().parents[1]
VERSION = "4.13.1"
SHA256 = "bc13a9c57a8dd7d5196888211e5ede657cb64a3ce968608697e4f668251a8487"
GRAMMAR = ROOT / "pkg/config_parser/grammar"
DESTINATION = ROOT / "pkg/config_parser/internal/dae_config"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="check without replacing generated sources")
    args = parser.parse_args()
    jar = ROOT / "build/tools" / f"antlr-{VERSION}-complete.jar"
    if not jar.exists():
        with urlopen(f"https://www.antlr.org/download/{jar.name}", timeout=60) as response:
            data = response.read()
        if hashlib.sha256(data).hexdigest() != SHA256:
            raise SystemExit("ANTLR download checksum mismatch")
        jar.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=jar.parent, delete=False) as download:
            download.write(data)
        Path(download.name).replace(jar)
    if hashlib.sha256(jar.read_bytes()).hexdigest() != SHA256:
        raise SystemExit(f"ANTLR checksum mismatch: {jar}")

    with tempfile.TemporaryDirectory(prefix="dae-config-parser-") as directory:
        output = Path(directory)
        subprocess.run([
            "java", "-jar", str(jar), "-Dlanguage=Go", "-package", "dae_config",
            "-o", str(output), "dae_config.g4",
        ], cwd=GRAMMAR, check=True)
        subprocess.run(["gofmt", "-w", *map(str, sorted(output.glob("*.go")))], check=True)
        generated = {path.name for path in output.iterdir()}
        existing = {path.name for path in DESTINATION.glob("dae_config*")}
        changed = sorted(name for name in generated | existing
                         if name not in generated or name not in existing
                         or (output / name).read_bytes() != (DESTINATION / name).read_bytes())
        if args.check:
            if changed:
                raise SystemExit("Config parser is stale; run make config-parser: " + ", ".join(changed))
            print("Config parser matches grammar and ANTLR " + VERSION)
            return
        DESTINATION.mkdir(parents=True, exist_ok=True)
        for name in existing - generated:
            (DESTINATION / name).unlink()
        for name in generated:
            shutil.copyfile(output / name, DESTINATION / name)
        print("Generated config parser with ANTLR " + VERSION)


if __name__ == "__main__":
    main()
