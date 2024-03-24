# SPDX-FileCopyrightText: 2024 H Phil Duby
# SPDX-License-Identifier: MIT

"""prototyping dynamic import and error handling """

import importlib
from types import ModuleType
import logging

def import_module(module_name: str) -> ModuleType:
    """
    Dynamically imports a module based on its textual path.

    Args:
        module_name (str): The textual path of the module to be imported.

    Returns:
        ModuleType: The imported module.

    Raises:
        ImportError: If the module cannot be found or loaded.
        AttributeError: For attribute-related errors, such as incorrect module name types.
        Exception: For any unexpected errors during the import process.
    """
    try:
        module = importlib.import_module(module_name)
        logging.info('Successfully imported module: %s', module_name)
        return module
    except ImportError as e:
        if isinstance(e, ModuleNotFoundError):
            if e.name == module_name:
                logging.error('Module "%s" not found. Please check the module name '
                              'and ensure it is installed.', module_name)
            else:
                logging.error('Required dependency "%s" was not found while importing "%s". '
                              'Please install it and retry.', e.name, module_name)
        else:
            logging.error('Error importing module "%s": %s\n Please correct the '
                          'problem then retry.', module_name, e)
        raise
    except AttributeError as e:
        if e.name == 'startswith':
            logging.error('The module name "%s" is not a string. Please provide '
                          'a valid string for the module name.', module_name)
        else:
            logging.error('Attribute error while importing module "%s": %s', module_name, e)
        raise
    except Exception as e:
        logging.error('Unexpected error (%s) during module "%s" import: %s',
                      type(e).__name__, module_name, e)
        raise

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
