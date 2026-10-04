"""Unit converter CLI for the ops team."""
import sys

import requests
import click


@click.command()
@click.argument("spec")
def main(spec: str) -> None:
    r = requests.get("http://127.0.0.1:9000/convert", params={"q": spec}, timeout=5)
    click.echo(r.text)


if __name__ == "__main__":
    sys.exit(main())
