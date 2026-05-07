from __future__ import annotations

import logging
import signal
import sys
from typing import List, Optional

from katzenpost_reticulum.pkimirror.bridge import ThinClientBridge
from katzenpost_reticulum.pkimirror.cache import PkiCache
from katzenpost_reticulum.pkimirror.config import parse_args
from katzenpost_reticulum.pkimirror.dirauth_config import load_dirauth_config
from katzenpost_reticulum.pkimirror.service import PkiMirrorService

logger = logging.getLogger("pkimirror")


def main(argv: Optional[List[str]] = None) -> int:
    cfg = parse_args(argv)
    logging.basicConfig(
        level=cfg.log_level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    logger.info(
        "pkimirror is preparing to take its station; thinclient config: %s.",
        cfg.thinclient_config,
    )

    load_dirauth_config(cfg.dirauth_config)

    cache = PkiCache(max_epochs=5)
    service = PkiMirrorService(
        cache=cache,
        identity_path=cfg.identity_path,
        app_name=cfg.app_name,
        aspects=cfg.aspects,
        announce_interval=cfg.announce_interval,
        stale_after=cfg.stale_after,
        reticulum_config=cfg.rns_config,
    )
    cache.set_on_new_epoch(service.notify_epoch_advance)

    bridge = ThinClientBridge(cfg.thinclient_config, cache)

    def _handle_signal(_signum, _frame):
        logger.info("Signal received; shutting down at the next convenience.")
        service.shutdown()

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    try:
        bridge.start()
    except Exception:
        logger.exception("Could not establish thin-client bridge; aborting.")
        return 1

    try:
        service.run()
    except Exception:
        logger.exception("pkimirror service terminated with an exception.")
        return 1
    finally:
        bridge.stop()
        logger.info("pkimirror has retired for the evening.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
