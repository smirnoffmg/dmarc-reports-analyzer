#!/usr/bin/env python
import glob
import os
import tempfile
import shutil
import typing as t
from dataclasses import dataclass
from pathlib import Path
from zipfile import ZipFile
import gzip
import pandas as pd
import click
from bs4 import BeautifulSoup as bs


@dataclass
class AuthResult:
    source: str
    dkim: str
    spf: str
    disposition: str

    @classmethod
    def from_xml(cls, xml_node) -> "AuthResult":
        return cls(
            source=xml_node.row.source_ip.text,
            dkim=xml_node.row.policy_evaluated.dkim.text,
            spf=xml_node.row.policy_evaluated.spf.text,
            disposition=xml_node.row.policy_evaluated.disposition.text,
        )


def prepare_files(path: str) -> None:
    frame: t.List[AuthResult] = []

    with tempfile.TemporaryDirectory() as tmpdirname:
        for filepath in glob.glob(f"{path}/*.zip", recursive=True):
            with ZipFile(filepath, "r") as zip_obj:
                zip_obj.extractall(tmpdirname)

        for filepath in glob.glob(f"{path}/*.gz", recursive=True):
            filename = os.path.basename(filepath)
            with gzip.open(filepath, "rb") as gzip_obj:
                with open(f"{tmpdirname}/{filename}.xml", "wb") as f_out:
                    shutil.copyfileobj(gzip_obj, f_out)

        for filepath in glob.glob(f"{tmpdirname}/*.xml", recursive=True):
            frame.extend(process_xml(filepath))

    df = pd.DataFrame(frame)
    print(df)


def process_xml(filepath: str) -> t.List[AuthResult]:
    with open(filepath, "r") as _file:
        bs_content = bs(_file.read(), "lxml")

    result = []

    for row in filter(lambda i: i.name, bs_content.feedback):
        if row.name == "record":
            result.append(AuthResult.from_xml(row))

    return result


@click.command()
@click.option(
    "--reports",
    prompt="Path to directory with DMARC reports",
    help="Path to directory with DMARC reports",
)
def main(reports: str):

    path = Path(reports).resolve()

    click.echo(f"Working with reports at {path}")

    prepare_files(str(path))


if __name__ == "__main__":
    main()