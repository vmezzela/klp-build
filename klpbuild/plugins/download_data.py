# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2025 SUSE
# Author: Vincenzo Mezzela <vincenzo.mezzela@suse.com>

import logging

from klpbuild.klplib.utils import classify_codestreams_str
from klpbuild.klplib.supported import get_supported_codestreams
from klpbuild.klplib.ibs import IBS

PLUGIN_CMD = "download-data"

def register_argparser(subparser):
    fmt = subparser.add_parser(
        PLUGIN_CMD, help="SLE specific. Extract patches from kgraft-patches"
    )
    fmt.add_argument("-d", "--download_missing", action="store_true", help="Download all the required data")


def run(download_missing):
    if download_missing:
        download_missing_data()
    else:
        logging.info("use --download")


def download_missing_data():
    data_missing = __get_missing_data()
    download_codestreams_data(data_missing)


def download_codestreams_data(codestreams):
    logging.info("Download the necessary data from the following codestreams: %s", classify_codestreams_str(codestreams))
    IBS("", "").download_cs_data(codestreams)
    logging.info("Done.")


def __get_missing_data():
    data_missing = []
    for cs in get_supported_codestreams():
        if not cs.get_boot_file("config").exists():
            data_missing.append(cs)

    logging.debug("Missing data found: %s", classify_codestreams_str(data_missing))
    return data_missing
