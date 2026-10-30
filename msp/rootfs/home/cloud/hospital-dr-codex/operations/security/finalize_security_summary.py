#!/usr/bin/env python3
"""Finalize a CI security summary after immutable ECR push."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def finalize(input_path, output_path, ecr_push, digest=""):
    document = json.loads(Path(input_path).read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError("security summary must be an object")
    document["ecr_push"] = str(ecr_push).upper()
    if digest:
        document["ecr_image_digest"] = str(digest)
    Path(output_path).write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return document


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--ecr-push", required=True, choices=("PASS", "FAIL", "SKIPPED"))
    parser.add_argument("--digest", default="")
    args = parser.parse_args(argv)
    finalize(args.input, args.output, args.ecr_push, args.digest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
