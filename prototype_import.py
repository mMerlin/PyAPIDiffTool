# SPDX-FileCopyrightText: 2024 H Phil Duby
# SPDX-License-Identifier: MIT

"""prototyping dynamic import and error handling"""

import logging
from generic_tools import import_module

def test_module_import(module_name: str):
    """
    Dynamically import a single module with error trapping.

    Args:
        module_name (str): name to use as a module name to import
    """
    try:
        imported_module = import_module(module_name)
        print(f'{len(dir(imported_module))} attributes in {module_name} module')
        # Perform operations with the imported module...
    except Exception:  # pylint:disable=broad-exception-caught
        # In theory, the exceptions have all been handled already, at least for the prototype
        pass

if __name__ == "__main__":
    module_names = [
        "os.path",
        "json",
        "nonexistentmodule",
        "«bad module µ¦© name»",
        "lib.adafruit_logging",
        "lib.prototype_logging",
        None,
        ('tuple', 'module'),
        -54,
    ]
    # Setup basic logging configuration
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
    for name in module_names:
        test_module_import(name)

# cSpell:words adafruit, levelname
# cSpell:ignore nonexistentmodule
