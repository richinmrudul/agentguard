#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agentguard.evaluation.runtime_images import (  # noqa: E402
    RuntimeImageError,
    canonical_rootfs_digest,
    canonical_runtime_config,
    canonical_runtime_identity,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image-role", choices=("gateway", "agent"), required=True)
    parser.add_argument("--base-image", required=True)
    parser.add_argument("--inspect-json", type=Path, required=True)
    parser.add_argument("--rootfs-tar", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        inspect_data = json.loads(args.inspect_json.read_text(encoding="utf-8"))
        rootfs_digest = canonical_rootfs_digest(args.rootfs_tar)
        identity = canonical_runtime_identity(
            image_role=args.image_role,
            base_image=args.base_image,
            rootfs_digest=rootfs_digest,
            runtime_config=canonical_runtime_config(inspect_data),
        )
        args.output.write_text(
            json.dumps(identity, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except (OSError, json.JSONDecodeError, RuntimeImageError) as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
