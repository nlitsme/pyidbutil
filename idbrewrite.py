# written by chatgpt GPT-6
"""Rewrite an IDB container, preserving semantic records and database width."""
import argparse
from pathlib import Path

import idblib


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--compress-id0', action='store_true')
    args = parser.parse_args()
    # Exclusive creation refuses existing output paths, including the source.
    created = False
    try:
        with args.source.open('rb') as source:
            with args.output.open('xb+') as output:
                created = True
                idblib.updateidb(source, output, compression=2 if args.compress_id0 else 0)

    except BaseException:
        if created:
            args.output.unlink()
        raise


if __name__ == '__main__':
    main()
