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

import sys
from typing import Union, Dict, Any, FrozenSet
from dataclasses import dataclass
import argparse
import configparser
from pathlib import Path
import logging
from generic_tools import (
    SentinelTag,
    add_tri_state_argument, make_all_or_keys_validator, attribute_names_validator,
    get_config_path, get_config_file, process_keyword_settings,
    validate_attribute_names,
)

ConfigurationType = Union[bool, str, set, Dict[str, Any]]

@dataclass
class IniKey:
    """
    keys for configuration (ini) file entries.
    """
    # pylint:disable=too-many-instance-attributes
    main: str = 'Main'
    report: str = 'Report'
    ignore: str = 'Ignore'
    scope: str = 'attribute-scope'
    exact: str = 'exact-match'
    matched: str = 'matched'
    not_imp: str = 'not-implemented'
    extensions: str = 'extensions'
    skipped: str = 'skipped'
    builtin: str = 'builtin-filter'
    global_attr: str = 'global-attributes'
    module_attr: str = 'module-attributes'
    class_attr: str = 'class-attributes'
    docstring: str = 'docstring'
    annotation: str = 'added-annotation'

@dataclass
class CfgKey:
    """
    keys for configuration setting entries.
    """
    # pylint:disable=too-many-instance-attributes
    scope: str = 'attribute_scope'
    good_scope: FrozenSet = frozenset({'all', 'public', 'published'})
    report: str = 'report_settings'
    report_bools: FrozenSet = frozenset({'exact', 'matched', 'not_imp', 'extensions', 'skipped'})
    ignore: str = 'ignore_settings'
    ignore_bools: FrozenSet = frozenset({'builtin'})
    ignore_sets: FrozenSet = frozenset({'global_attr', 'module_attr', 'class_attr', 'docstring',
                                        'annotation'})
    exact: str = 'exact_match'
    matched: str = 'matched'
    not_imp: str = 'not_implemented'
    extensions: str = 'extensions'
    skipped: str = 'skipped'
    builtin: str = 'builtin_filters'
    global_attr: str = 'global_attributes'
    module_attr: str = 'module_attributes'
    class_attr: str = 'class_attributes'
    docstring: str = 'docstring'
    annotation: str = 'added_annotation'
    context_suffix: str = '_contexts'
    docstring_contexts: FrozenSet = frozenset({'module', 'class', 'method'})
    annotation_contexts: FrozenSet = frozenset({'parameter', 'return', 'scope'})
    negation_prefix: str = 'no-'

@dataclass
class Tag:
    """
    keys for SentinelTag instances.
    """
    no_entry: str = 'No entry exists'

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
        print(self._configuration_settings)  # DEBUG

    def _default_configuration(self) -> ConfigurationType:
        """The builtin base (default) configuration settings"""
        def_cfg: Dict[str, ConfigurationType] = {
            CfgKey.report: {
                CfgKey.exact: False,
                CfgKey.matched: False,
                CfgKey.not_imp: False,
                CfgKey.extensions: False,
                CfgKey.skipped: False,
            },
            CfgKey.ignore: {
                CfgKey.builtin: False,
                CfgKey.global_attr: set(),
                CfgKey.module_attr: set(),
                CfgKey.class_attr: set(),
                CfgKey.docstring: set(),
                CfgKey.annotation: set(),
            },
            CfgKey.scope: "all",
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
        negate = CfgKey.negation_prefix
        keys = CfgKey.docstring_contexts
        parser.add_argument(
            '--ignore-docstring', metavar='CONTEXTS',
            type=make_all_or_keys_validator(keys, negation=negate),
            help="Specify contexts to ignore docstring changes in: 'all' or comma-separated list "
            f"of contexts {{{', '.join(keys)}}}. Use '{negate}<context>' to exclude (not ignore). "
            'Surround list with quotes if spaces included after commas.')
        keys = CfgKey.annotation_contexts
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
        parser.add_argument('--config-file', action='append',
                            help='Specify a configuration file to load.')
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
        if self._raw_args.create_config:
            self.output_default_ini()
            sys.exit()
        if self._raw_args.no_user_config:
            self._load_configuration_file(self._user_config_path())
        if self._raw_args.no_project_config:
            self._load_configuration_file(self._project_config_path())
        if self._raw_args.config_file:
            for cfg_file in self._raw_args.config_file:
                if not self._load_configuration_file(Path(cfg_file)):
                    logging.error('configuration file "%s" requested on the command line '
                                'could not be loaded', cfg_file)

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

    def _load_configuration_file(self, file_path: Path) -> bool:
        """
        Merge settings from a specified configuration file

        configparser has the capability to read multiple configuration files, then provide
        an interface to the merged result. That does not fit well with sequential (cascaded)
        processing of some values, like the context keywords for ignoring docstrings and
        added annotation. For those, one configuration file might turn them all on, then a
        later one turn specific contexts back off. Allowing configparser to merge that
        would mean that only the final keyword would be seen.

        Args:
            file_path (Path) the path to the configuration file

        Returns
            (bool): True if the requested file was loaded, False otherwise
        """
        config: configparser.ConfigParser = get_config_file(file_path)
        if config is None:
            return False

        self._load_configuration_main(config, file_path)
        self._load_configuration_report(config, file_path)
        self._load_configuration_ignore(config, file_path)
        logging.info('settings loaded from "%s"', file_path)
        return True

    def _load_configuration_main(self, cfg: configparser.ConfigParser, source: Path) -> None:
        """
        Load [Main] configuration file section data to application configuration.

        Args:
            cfg (ConfigParser): parser with loaded configuration file data
            source (Path): the path to the configuration file
        """
        if IniKey.main not in cfg.sections():
            return
        section = cfg[IniKey.main]

        cfg_value = section.get(IniKey.scope, fallback=SentinelTag(Tag.no_entry))
        if cfg_value is not SentinelTag(Tag.no_entry):
            if cfg_value in CfgKey.good_scope:
                self._configuration_settings[CfgKey.scope] = cfg_value
            else:
                logging.error('Invalid attribute-scope entry "%s" found in "%s"', cfg_value, source)

    def _load_configuration_report(self, cfg: configparser.ConfigParser, _source: Path) -> None:
        """
        Load [Report] configuration file section data to application configuration.

        Args:
            cfg (ConfigParser): parser with loaded configuration file data
            source (Path): the path to the configuration file
        """
        if IniKey.report not in cfg.sections():
            return
        section = cfg[IniKey.report]
        block = self._configuration_settings[CfgKey.report]

        for key in CfgKey.report_bools:
            _set_bool_from_config(section, block, key)

    def _load_configuration_ignore(self, cfg: configparser.ConfigParser, _source: Path) -> None:
        """
        Load [Ignore] configuration file section data to application configuration.

        Args:
            cfg (ConfigParser): parser with loaded configuration file data
            source (Path): the path to the configuration file
        """
        if IniKey.ignore not in cfg.sections():
            return
        section = cfg[IniKey.ignore]
        block = self._configuration_settings[CfgKey.ignore]

        for key in CfgKey.ignore_bools:
            _set_bool_from_config(section, block, key)
        for key in CfgKey.ignore_sets:
            configuration_set: set = block[getattr(CfgKey, key)]
            _update_set_from_config(section, configuration_set, key)

def _set_bool_from_config(section: configparser.SectionProxy, block: Dict[str, bool],
                          key: str) -> None:
    """
    Sets a boolean configuration value based on a configuration file entry.

    Does nothing if no matching entry is found in the section.

    Args:
        section (SectionProxy): the configparser section with the entry
        block (Dict[str, bool]): the internal configuration dictionary to hold the value
        key (str): the lookup key to locate the ini and configuration setting entries
    """
    ini_key = getattr(IniKey, key)
    cfg_value: str = section.get(ini_key, fallback=SentinelTag(Tag.no_entry))
    if cfg_value is not SentinelTag(Tag.no_entry):
        block[getattr(CfgKey, key)] = section.getboolean(ini_key)

def _update_set_from_config(section: configparser.SectionProxy, target: set[str], key: str) -> None:
    """
    Updates configuration set based on a configuration file entry.

    Does nothing if no matching entry is found in the section.

    Args:
        section (SectionProxy): the configparser section with the entry
        target (set[str]): the internal configuration set to update
        key (str): the lookup key to locate the ini and configuration setting entries
    """
    ini_key: str = getattr(IniKey, key)
    cfg_value: str = section.get(ini_key, fallback=SentinelTag(Tag.no_entry))
    if cfg_value and cfg_value is not SentinelTag(Tag.no_entry):
        good_set: FrozenSet = getattr(CfgKey, key + CfgKey.context_suffix,
                                      SentinelTag(Tag.no_entry))
        if good_set is SentinelTag(Tag.no_entry):
            # no validation set: everything else is attribute names
            target.update(validate_attribute_names(cfg_value))
        else:
            _update_set_keywords(target, cfg_value, good_set)

def _update_set_keywords(target: set[str], keywords: str, valid: FrozenSet[str]) -> None:
    """
    update keyword parameters in an existing configuration set

    This uses the same logic as attribute_names_validator used to validate command line
    arguments. With the wrapper function needed there, and the different exception handling,
    refactoring to DRY the code looks complicated.

    Args:
        target (set): the existing keyword set to update
        keywords (str): comma-separated list of context keywords (possibly negated)
        valid (Frozenset): the valid context keywords, without 'all' or negated version
    """
    states = process_keyword_settings(keywords, valid)
    for key, state in states.items():
        if state:
            target.add(key)
        else:
            target.remove(key)


if __name__ == "__main__":
    app = CompareModuleAPI()

# cSpell:words configparser pathlib expanduser getboolean posix getint getfloat metavar issubset
# cSpell:ignore nargs
# cSpell:allowCompoundWords true
