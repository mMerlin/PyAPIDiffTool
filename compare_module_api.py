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
from typing import Union, Dict, Any, FrozenSet, Set
from dataclasses import dataclass
import argparse
import configparser
from pathlib import Path
import logging
from generic_tools import (
    SentinelTag, IniStr, IniStructureType,
    add_tri_state_argument, make_all_or_keys_validator, attribute_names_validator,
    get_config_path, get_config_file, update_set_keywords,
    validate_attribute_names, generate_ini_file
)

ConfigurationType = Union[bool, str, set, Dict[str, Any]]

@dataclass(frozen=True)
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

@dataclass(frozen=True)
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

@dataclass(frozen=True)
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

    def __init__(self):
        self._configuration_settings: Dict[str, ConfigurationType] = self._default_configuration()
        # Parse arguments related to configuration files first
        cmd_line_parser = self._create_command_line_parser()
        self._raw_args = cmd_line_parser.parse_args()
        print(self._raw_args)  # DEBUG
        self.process_configuration_files()
        self.apply_command_line_arguments_to_configuration()
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

    def output_default_ini(self) -> None:
        """
        Output (to standard output) the default application configuration file with
        embedded documentation.
        """
        # pylint:disable=line-too-long
        def_reference = self._default_configuration()
        ini_details: IniStructureType = {
            IniKey.main: {
                IniStr.description: '''Documented CompareModuleAPI configuration template file

This provides information about configuration entry settings, including valid
and default values.

Multiple configuration files can be used. Each file modifies the state of the
configuration left by the previous file. The first configuration file read, if it
exists, will be from the operating system specific user application configuration
folder. On linux, this will be ~/.config/CompareModuleAPI/CompareModuleAPI.ini
On Windows, it will be %APPDATA%/CompareModuleAPI/CompareModuleAPI.ini
On Mac, it will be library/Application Support/CompareModuleAPI/CompareModuleAPI.ini
The user configuration file is not required for operation. Neither the folder
or user configuration file are automatically created.

Loading information from the user application configuration can be suppressed with
the "--no-user-config" command line option.

The next configuration read, if it exists, will be from the folder that the
application is being run from. The current working directory. Loading information
from the project configuration can be suppressed with the "--no-project-config"
command line option.

Additional configuration files can be specified from the command line with the
"--config-file CONFIG_FILE" option. This can be specified multiple times. The
file are loaded in the order the options are specified.

Main section''',
                IniStr.settings: {
                    CfgKey.scope: {
                        IniStr.doc: '''Set the scope of the attribute comparisons between the base and port package
implementations. 'all' is all attribute names that can be seen with dir().
'published' limits the comparison to attribute names that are in the 'all'
attribute (where) that exists. Public removes dunder and private attribute
names from 'all'.

all and public are straight forward for both base and port implementations.
published can be a little odd. Only published attribute names are considered
in the base implementation, but all port attribute names are initially
included for port. This is done to identify cases where an attribute published
in base exists in port, but was not published in the port implementation. The
reverse case will be reported as an extension in the port implementation.
''',
                        IniStr.default: def_reference[CfgKey.scope],
                        IniStr.comment: 'choose one of: all, public, published'
                    }
                }
            },
            IniKey.report: {
                IniStr.description: '''Report configuration section controls what parts of the comparison result are
included in the final report.''',
                IniStr.settings: {
                    CfgKey.exact: {
                        IniStr.doc: '''Include attribute names with exactly matching signatures in the match
differences report.''',
                        IniStr.default: str(def_reference[CfgKey.report][CfgKey.exact]),
                        IniStr.comment: "boolean: True or False"
                    },
                    CfgKey.matched: {
                        IniStr.doc: '''Include report section for attributes with matching names but differing
signatures.''',
                        IniStr.default: str(def_reference[CfgKey.report][CfgKey.matched]),
                        IniStr.comment: "boolean: True or False"
                    },
                    CfgKey.not_imp: {
                        IniStr.doc: "Include report section for attributes not implemented in the port module.",
                        IniStr.default: str(def_reference[CfgKey.report][CfgKey.not_imp]),
                        IniStr.comment: "boolean: True or False"
                    },
                    CfgKey.extensions: {
                        IniStr.doc: '''Include report section for attributes implemented in the port
implementation but not in the base.''',
                        IniStr.default: str(def_reference[CfgKey.report][CfgKey.extensions]),
                        IniStr.comment: "boolean: True or False"
                    },
                    CfgKey.skipped: {
                        IniStr.doc: "Include report section for attribute names that were skipped during the comparison.",
                        IniStr.default: str(def_reference[CfgKey.report][CfgKey.skipped]),
                        IniStr.comment: "boolean: True or False"
                    },
                }
            },
            IniKey.ignore: {
                IniStr.description: '''Ignore configuration section allows specifying attribute names or aspects to be
ignored during comparison.

For the entries that allow 'contexts' to be specified, 'all' enables all valid
contexts. To disable a context (possibly previously enable by a different
configuration file), prefix the context with 'no-'. The general format is:
all or [no-]<context1>[,[no-]<context2>]...''',
                IniStr.settings: {
                    CfgKey.builtin: {
                        IniStr.doc: '''Ignore attributes that are considered built-in functionality (common across
many modules).''',
                        IniStr.default: str(def_reference[CfgKey.ignore][CfgKey.builtin]),
                        IniStr.comment: "boolean: True or False"
                    },
                    CfgKey.global_attr: {
                        IniStr.doc: "Comma-separated list of attribute names to ignore in all contexts.",
                        IniStr.default: ','.join(def_reference[CfgKey.ignore][CfgKey.global_attr]),
                        IniStr.comment: "list of attribute names"
                    },
                    CfgKey.module_attr: {
                        IniStr.doc: "Comma-separated list of attribute names to ignore when processing an module.",
                        IniStr.default: ','.join(def_reference[CfgKey.ignore][CfgKey.module_attr]),
                        IniStr.comment: "list of attribute names"
                    },
                    CfgKey.class_attr: {
                        IniStr.doc: "Comma-separated list of attribute names to ignore when processing a class.",
                        IniStr.default: ','.join(def_reference[CfgKey.ignore][CfgKey.class_attr]),
                        IniStr.comment: "list of attribute names"
                    },
                    CfgKey.docstring: {
                        IniStr.doc: ''''all' or a comma-separated list of contexts to ignore differences in docstring
values.''',
                        IniStr.default: ','.join(def_reference[CfgKey.ignore][CfgKey.docstring]),
                        IniStr.comment: "contexts: module, class, method"
                    },
                    CfgKey.annotation: {
                        IniStr.doc: ''''all' or a comma-separated list of contexts to ignore annotations that exist
in the port implementation where none was defined for base. These are all
related to method (or function) signatures.
- method parameter typehint
- method return value typehint
- scope is for any entry in the parent class __annotation__ dictionary''',
                        IniStr.default: ','.join(def_reference[CfgKey.ignore][CfgKey.annotation]),
                        IniStr.comment: "contexts: parameter, return, scope"
                    },
                }
            },
        }
        generate_ini_file(sys.stdout, ini_details)

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

    def process_configuration_files(self):
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
            _update_set_from_config(section, block, key)

    def apply_command_line_arguments_to_configuration(self):
        """Updates configuration settings based on command-line arguments."""
        # Implementation to update configuration from args goes here

        # for key, value in vars(self.args).items():
        #     if value is not None:
        #         self._configuration_settings[key] = value
        if self._raw_args.report_exact_match is None:
            print("Report flag was not explicitly set.")
        else:
            print(f"Report flag explicitly set to: {self._raw_args.report_exact_match}")

    def _user_config_path(self) -> Path:
        """
        get the path to the user configuration file

        This needs to be smarter, to be platform agnostic? sensitive?.

        returns (str) the path to the users' application configuration file
        """
        return get_config_path(self.APP_NAME) / f'{self.APP_NAME}.ini'

    def _project_config_path(self) -> Path:
        """
        get the path to the project configuration file

        returns (str) the path to the project application configuration file
        """
        return Path.cwd() / f'{self.APP_NAME}.ini'

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

def _update_set_from_config(section: configparser.SectionProxy, block: Dict[str, Set[str]],
                            key: str) -> None:
    """
    Updates configuration set based on a configuration file entry.

    Does nothing if no matching entry is found in the section.

    Args:
        section (SectionProxy): the configparser section with the entry
        target (set[str]): the internal configuration set to update
        key (str): the lookup key to locate the ini and configuration setting entries
    """
    target: set = block[getattr(CfgKey, key)]
    ini_key: str = getattr(IniKey, key)
    cfg_value: str = section.get(ini_key, fallback=SentinelTag(Tag.no_entry))
    if cfg_value and cfg_value is not SentinelTag(Tag.no_entry):
        good_set: FrozenSet = getattr(CfgKey, key + CfgKey.context_suffix,
                                      SentinelTag(Tag.no_entry))
        if good_set is SentinelTag(Tag.no_entry):
            # no keyword validation set: everything else is attribute names
            target.update(validate_attribute_names(cfg_value))
        else:
            update_set_keywords(target, cfg_value, good_set, negation_prefix=CfgKey.negation_prefix)


if __name__ == "__main__":
    app = CompareModuleAPI()

# pylint:disable=line-too-long
# cSpell:words configparser pathlib expanduser getboolean posix getint getfloat metavar issubset docstrings dunder
# cSpell:ignore nargs appdata
# cSpell:allowCompoundWords true
