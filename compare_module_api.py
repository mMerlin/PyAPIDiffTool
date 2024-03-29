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

import os
import sys
from typing import Union, Dict, Any
import argparse
import configparser
from pathlib import Path #, PosixPath
import logging
from app_error_framework import ApplicationLogicError
from generic_tools import (
    add_tri_state_argument, make_all_or_keys_validator, attribute_names_validator,
    get_config_path,
)

ConfigurationType = Union[bool, str, set, Dict[str, Any]]

class CompareModuleAPI:
    """Compares module APIs for compatibility between different implementations.

    This class provides functionality to compare the interfaces of modules, classes, and functions,
    highlighting differences that might affect compatibility. It supports loading configuration from
    files and command-line arguments to customize the comparison process.

    Attributes:
        _configuration_settings (dict): Stores the application's configuration settings.
        args (Namespace): Command-line arguments parsed by argparse.
    """
    APP_NAME = 'CompareModuleAPI'
    MAIN_SECTION = 'Main'
    CFG_KEY_SUFFIX = '_settings'

    def __init__(self):
        self._configuration_settings: Dict[str, ConfigurationType] = self._default_configuration()
        # Parse arguments related to configuration files first
        cmd_line_parser = self._create_command_line_parser()
        self._raw_args = cmd_line_parser.parse_args()
        print(self._raw_args)  # DEBUG
        self._process_configuration_files()
        self._apply_command_line_arguments_to_configuration()

    def _default_configuration(self) -> ConfigurationType:
        """The builtin base (default) configuration settings"""
        def_cfg: Dict[str, ConfigurationType] = {
            "report_settings": {
                "exact_match": False,
                "matched": False,
                "not_implemented": False,
                "extensions": False,
                "skipped": False,
            },
            "ignore_settings": {
                "builtin_filters": False,
                "global_attributes": set(),
                "module_attributes": set(),
                "class_attributes": set(),
                "docstring": set(),
                "added_annotations": set(),
            },
            "attribute_scope": "all",
        }
        return def_cfg

    def _create_command_line_parser(self) -> argparse.ArgumentParser:
        """Creates parser for command-line arguments to configure the application."""
        parser = argparse.ArgumentParser(description='Compare module APIs.')
        parser.add_argument('--version', action='version', version='%(prog)s 0.0.1')

        parser.add_argument('--attribute-scope', choices=['all', 'public', 'published'],
                            help='Scope of attributes to compare.')
        add_tri_state_argument(parser, '--report-exact-match',
                               'Include attributes with exact matches in report.')
        add_tri_state_argument(parser, '--ignore-builtin-filters',
                               'Do not filter out the default attribute names.')
        parser.add_argument(
            '--ignore-module-attributes', metavar='MODULE_ATTRIBUTES',
            type=attribute_names_validator,
            help='Comma-separated list of attributes to ignore in module context. '
            'Surround list with quotes if spaces included after commas.')
        parser.add_argument(
            '--ignore-global-attributes', metavar='GLOBAL_ATTRIBUTES',
            type=attribute_names_validator,
            help='Comma-separated list of attributes to ignore in all contexts. '
            'Surround list with quotes if spaces included after commas.')
        parser.add_argument(
            '--ignore-class-attributes', metavar='CLASS_ATTRIBUTES',
            type=attribute_names_validator,
            help='Comma-separated list of attributes to ignore in class context. '
            'Surround list with quotes if spaces included after commas.')
        negate = 'no-'
        keys = ('module', 'class', 'method')
        parser.add_argument(
            '--ignore-docstring', metavar='CONTEXTS',
            type=make_all_or_keys_validator(keys, negation=negate),
            help="Specify contexts to ignore docstring changes in: 'all' or comma-separated list "
            f"of contexts {{{', '.join(keys)}}}. Use '{negate}<context>' to exclude (not ignore). "
            'Surround list with quotes if spaces included after commas.')
        keys = ('parameter', 'return', 'scope')
        parser.add_argument(
            '--ignore-added-annotations', metavar='CONTEXTS',
            type=make_all_or_keys_validator(keys, negation=negate),
            help="Specify contexts to ignore added annotations: 'all' or comma-separated list of "
            f"contexts {{{', '.join(keys)}}}. Use '{negate}<context>' to exclude (not ignore). "
            'Surround list with quotes if spaces included after commas.')
        add_tri_state_argument(parser, '--report-matched',
                               'Generate report for differences in matched attributes.')
        add_tri_state_argument(parser, '--report-not-implemented',
                               'Generate report for attributes not implemented in the port.')
        add_tri_state_argument(parser, '--report-extensions',
                               'Generate report for extensions implemented in the port.')
        add_tri_state_argument(parser, '--report-skipped',
                               'Generate report for attributes that were skipped.')

        # Configuration file arguments
        parser.add_argument('--config-file', help='Specify a configuration file.')
        parser.add_argument('--no-user-config', action='store_false',
                            help='Do not load the user configuration file.')
        parser.add_argument('--no-project-config', action='store_false',
                            help='Do not load the project configuration file.')
        parser.add_argument('--create-config', action='store_true',
                            help='Create a configuration file with default settings.')

        # HPD package path arguments (base and port)

        return parser

    def _process_configuration_files(self):
        """Handles command-line arguments related to configuration files."""
        # Implementation to handle configuration file arguments goes here
        if self._raw_args.create_config:
            self.output_default_ini()
            sys.exit()
        if self._raw_args.no_user_config:
            self._load_configuration_file(self._user_config_path())
        if self._raw_args.no_project_config:
            self._load_configuration_file(self._project_config_path())
        if self._raw_args.config_file:
            self._load_configuration_file(self._raw_args.config_file)

    def output_default_ini(self) -> None:
        """Output (standard output) the default application configuration file"""
        # HPD fix this
        print(self._configuration_settings)  # need to structure output for ini file

    def _user_config_path(self) -> Path:
        """
        get the path to the user configuration file

        This needs to be smarter, to be platform agnostic? sensitive?.

        returns (str) the path to the users' application configuration file
        """
        return get_config_path(self.APP_NAME) / f'{self.APP_NAME}.ini'
        # return Path(os.path.expanduser(f'~/.config/{self.APP_NAME}.ini'))

    def _project_config_path(self) -> Path:
        """
        get the path to the project configuration file

        returns (str) the path to the project application configuration file
        """
        return Path.cwd() / f'{self.APP_NAME}.ini'

    def _apply_command_line_arguments_to_configuration(self):
        """Updates configuration settings based on command-line arguments."""
        # Implementation to update configuration from args goes here

        # for key, value in vars(self.args).items():
        #     if value is not None:
        #         self._configuration_settings[key] = value
        if self._raw_args.report_exact_match is None:
            print("Report flag was not explicitly set.")
        else:
            print(f"Report flag explicitly set to: {self._raw_args.report_exact_match}")

    # def _load_configuration_file(self, file_path: PosixPath) -> None:
    def _load_configuration_file(self, file_path: Path) -> None:
        """
        Merge settings from a specified configuration file

        Args:
            file_path (Path) the path to the configuration file
        """
        config = configparser.ConfigParser()

        # if not file_path.exists():
        if not file_path.is_file():
            logging.warning('Configuration file %s not found', file_path)
            return

        config.read(str(file_path))

        known_sections = [self.MAIN_SECTION] + \
                         [key[:-len(self.CFG_KEY_SUFFIX)].capitalize()
                          for key in self._configuration_settings
                          if key.endswith(self.CFG_KEY_SUFFIX)]

        for section in config.sections():
            if section not in known_sections:
                logging.info('skipping unknown section "%s" in configuration file %s',
                             section, repr(str(file_path)))
                continue

            # Determine the right configuration node (dictionary) to update
            cfg_node: dict = (self._configuration_settings if section == self.MAIN_SECTION
                        else self._configuration_settings.get(
                            section.lower() + self.CFG_KEY_SUFFIX, None))
            if cfg_node is None:
                raise ApplicationLogicError(f'Known ini section "{section}" does not have a ' +
                    f'matching configuration key "{section.lower() + self.CFG_KEY_SUFFIX}"')

            for key_name, value_str in config.items(section):
                key = key_name.replace('-', '_')
                if key not in cfg_node:
                    logging.info(f'ignoring unknown key {repr(key_name)} in section ' +
                                 f'"{section}" of configuration file {repr(str(file_path))}')
                    continue

                # Attempt to convert the value to the appropriate type based on the current setting
                current_value = cfg_node[key]
                if isinstance(current_value, bool):
                    cfg_node[key] = config.getboolean(section, key_name)
                elif isinstance(current_value, int):
                    cfg_node[key] = config.getint(section, key_name)
                elif isinstance(current_value, float):
                    cfg_node[key] = config.getfloat(section, key_name)
                elif isinstance(current_value, set):
                    cfg_node[key].update(set(value_str.split(',')))
                else:
                    cfg_node[key] = value_str

if __name__ == "__main__":
    app = CompareModuleAPI()
    # print(app._configuration_settings)  # pylint:disable=protected-access

# cSpell:words configparser pathlib expanduser getboolean posix getint getfloat metavar
# cSpell:ignore nargs
# cSpell:allowCompoundWords true
