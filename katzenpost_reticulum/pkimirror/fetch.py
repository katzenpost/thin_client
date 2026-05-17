"""A thin command-line client that fetches a PKI document from a
pkimirror over Reticulum.

This wraps :class:`PkiMirrorClient`: it discovers (or is told) a
mirror, opens a Link, fetches the current consensus (or a named
epoch), writes the raw document bytes to a file or stdout, and
reports the epoch, staleness, and verification status on stderr.

Run via the ``pkimirror-fetch`` console script, or
``python -m katzenpost_reticulum.pkimirror.fetch``.
"""

from __future__ import annotations

import argparse
import logging
import sys
from typing import List, Optional

from katzenpost_reticulum.pkimirror.client import (
    MirrorAnnouncement,
    PkiMirrorClient,
)
from katzenpost_reticulum.pkimirror.dirauth_config import load_dirauth_config
from katzenpost_reticulum.pkimirror.errors import PKIMIRROR_OK

logger = logging.getLogger("pkimirror-fetch")


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pkimirror-fetch",
        description="Fetch a Katzenpost PKI document from a pkimirror "
        "over Reticulum.",
    )
    p.add_argument(
        "--rns-config",
        default=None,
        help="Reticulum configuration directory. Defaults to the "
        "Reticulum default if omitted.",
    )
    p.add_argument(
        "--destination",
        default=None,
        help="pkimirror destination hash in hex. If omitted, the "
        "network is discovered and the freshest announced mirror "
        "chosen.",
    )
    p.add_argument(
        "--epoch",
        type=int,
        default=None,
        help="Fetch this specific epoch instead of the current "
        "consensus.",
    )
    p.add_argument(
        "--dirauth-config",
        default=None,
        help="Path to a dirauth identity TOML. When supplied, the "
        "cert.Certificate wrapper is verified against it.",
    )
    p.add_argument("--app-name", default="katzenpost")
    p.add_argument("--aspect", default="pkimirror")
    p.add_argument("--discover-timeout", type=float, default=30.0)
    p.add_argument("--connect-timeout", type=float, default=30.0)
    p.add_argument("--request-timeout", type=float, default=30.0)
    p.add_argument("--max-announces", type=int, default=3)
    p.add_argument(
        "--output",
        default=None,
        help="Write the raw document bytes here. Defaults to stdout.",
    )
    p.add_argument(
        "--log-level",
        default="WARNING",
        help="Logging level for diagnostics on stderr. Default "
        "WARNING so stdout stays a clean document stream.",
    )
    return p


def _select_destination(
    client: PkiMirrorClient, args: argparse.Namespace
) -> bytes:
    """Return the mirror destination hash, discovering one if the
    caller did not name it. Among announces, prefer those carrying a
    PKI document and then the highest epoch."""
    if args.destination is not None:
        return bytes.fromhex(args.destination)

    announces: List[MirrorAnnouncement] = client.discover(
        timeout=args.discover_timeout,
        max_announces=args.max_announces,
    )
    if not announces:
        raise RuntimeError(
            "no pkimirror announced within "
            f"{args.discover_timeout:.0f}s"
        )
    best = max(announces, key=lambda a: (a.has_pki, a.epoch))
    logger.info(
        "selected mirror %s (epoch %d, has_pki=%s) from %d announce(s)",
        best.destination_hash.hex(), best.epoch, best.has_pki,
        len(announces),
    )
    return best.destination_hash


def _write_output(path: Optional[str], doc: bytes) -> None:
    if path is None:
        sys.stdout.buffer.write(doc)
        sys.stdout.buffer.flush()
        return
    with open(path, "wb") as fh:
        fh.write(doc)


def main(argv: Optional[List[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    logging.basicConfig(
        level=args.log_level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    dirauth = (
        load_dirauth_config(args.dirauth_config)
        if args.dirauth_config is not None
        else None
    )

    try:
        with PkiMirrorClient(
            reticulum_config=args.rns_config,
            dirauth_config=dirauth,
            app_name=args.app_name,
            aspect=args.aspect,
        ) as client:
            destination = _select_destination(client, args)
            client.connect(destination, timeout=args.connect_timeout)
            if args.epoch is not None:
                result = client.get_for_epoch(
                    args.epoch,
                    timeout=args.request_timeout,
                    use_cache=False,
                )
            else:
                result = client.get_current(timeout=args.request_timeout)
    except Exception:
        logger.exception("pkimirror-fetch could not retrieve a document")
        return 1

    if result.code != PKIMIRROR_OK or result.doc is None:
        logger.error(
            "mirror returned code=%d (%s); epoch=%s",
            result.code, result.msg, result.epoch,
        )
        return 1

    _write_output(args.output, result.doc)
    logger.info(
        "fetched %d bytes; epoch=%s stale=%s verified=%s",
        len(result.doc), result.epoch, result.stale, result.verified,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
