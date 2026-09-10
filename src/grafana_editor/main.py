# SPDX-License-Identifier: MIT
from __future__ import annotations

import asyncio
import logging

import click
from hypercorn.asyncio import serve
from hypercorn.config import Config as HypercornConfig

from grafana_editor.config import Settings
from grafana_editor.server import create_app

DEFAULT_CONFIG_PATH = "/config/grafana-editor.toml"
LOG_FORMAT = "[%(asctime)s] [%(process)d] [%(levelname)s] %(name)s: %(message)s"

logger = logging.getLogger(__name__)


async def run(settings: Settings, disable_auth: bool) -> None:
    config = HypercornConfig()
    config.bind = [f"{settings.listen}:{settings.port}"]
    app = create_app(settings, disable_auth=disable_auth)
    await serve(app, config)  # ty: ignore[invalid-argument-type]


@click.command()
@click.option(
    "-c",
    "--config",
    "config_path",
    type=click.Path(exists=True, dir_okay=False, readable=True),
    default=DEFAULT_CONFIG_PATH,
    show_default=True,
    help="Path to the TOML configuration file.",
)
@click.option(
    "--disable-auth",
    is_flag=True,
    default=False,
    help="Disable Entra bearer-token authentication. For local development only.",
)
def main(config_path: str, disable_auth: bool) -> None:
    settings = Settings.from_toml(config_path)
    configure_logging(settings.log_level)
    logger.info("Starting grafana-editor")
    asyncio.run(run(settings, disable_auth))


def configure_logging(log_level: str) -> None:
    level = logging.getLevelNamesMapping()[log_level]
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    if not root_logger.handlers:
        logging.basicConfig(
            level=level,
            format=LOG_FORMAT,
            datefmt="%Y-%m-%d %H:%M:%S %z",
        )


if __name__ == "__main__":
    main()
