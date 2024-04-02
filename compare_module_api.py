# SPDX-FileCopyrightText: 2024 H Phil Duby
# SPDX-License-Identifier: MIT

"""
`compare module interfaces`
==================

Compare the visible api interface for different modules.

Written to see differences in CircuitPython specific module interfaces
compared to the standard cPython libraries.

This needs to run from cPython for its intended purpose. CircuitPython
does not implement some of the required libraries (inspect).

"""
from config_package import ProfileConfiguration, Setting

class CompareModuleAPI:  # pylint:disable=too-few-public-methods
    """Compares module APIs for compatibility between different implementations.

    This class provides functionality to compare the interfaces of modules, classes, and functions,
    highlighting differences that might affect compatibility. It supports loading configuration from
    files and command-line arguments to customize the comparison process.

    Attributes:
        _configuration_settings (dict): Stores the application's configuration settings.
        args (Namespace): Command-line arguments parsed by argparse.
    """
    APP_NAME: str = 'CompareModuleAPI'

    def __init__(self):
        self.settings = ProfileConfiguration(self.APP_NAME)
        # self.base_module = self.settings.get(Setting.BASE_MODULE_PATH)
        # self.port_module = self.settings.get(Setting.PORT_MODULE_PATH)
        self.base_module = self.settings.base
        self.port_module = self.settings.port
        _scope = self.settings[Setting.SCOPE.name]
        print(self.settings.keys())  # DEBUG


if __name__ == "__main__":
    app = CompareModuleAPI()

# cSpell:words
# cSpell:ignore
# cSpell:allowCompoundWords true
