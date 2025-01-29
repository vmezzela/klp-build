# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2025 SUSE
# Author: Vincenzo Mezzela <vincenzo.mezzela@suse.com>

import importlib
import logging

PLUGINS_PATH = "klpbuild.plugins."

def try_run_plugin(name, args):
    plugin = PLUGINS_PATH + name.replace("-", "_")

    logging.debug("Trying to run plugin %s", name)
    module = importlib.import_module(plugin)
    if not hasattr(module, "run"):
        raise ModuleNotFoundError(f"Module {name} is not a plugin!")
    module.run(args)
