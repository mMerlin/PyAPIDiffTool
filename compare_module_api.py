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
from collections import namedtuple
import argparse
import configparser
import copy
from pathlib import Path
import logging
from generic_tools import (
    SentinelTag, RunAndExitAction, IniStr, IniStructureType,
    add_tri_state_argument, validate_module_path, make_all_or_keys_validator,
    attribute_names_validator, get_config_path, get_config_file, update_set_keywords_from_string,
    update_set_keywords_from_dict, validate_attribute_names, generate_ini_file
)

ConfigurationType = Union[bool, str, set, Dict[str, Any]]
SettingKeys = namedtuple('SettingKeys', ['settings', 'ini', 'cli'])
'''
Keys (str) to access settings information in different contexts
settings: the internal configuration dictionary key
ini: the key in an ini configuration file
cli: the key to parsed command line argument information
'''

@dataclass(frozen=True)
class Part:
    """
    parts of configuration key attribute (field) names
    """
    option_type: str = 'options'
    bool_type: str = 'bools'
    set_type: str = 'sets'
    choice: str = 'choices'
    context: str = 'contexts'
    joiner: str = '_'

@dataclass(frozen=True)
class CfgKey:
    """
    keys for configuration setting entries.
    """
    # pylint:disable=too-many-instance-attributes
    main: SettingKeys = SettingKeys(settings=None, ini='Main', cli=None)
    report: SettingKeys = SettingKeys(settings='report_settings', ini='Report', cli=None)
    ignore: SettingKeys = SettingKeys(settings='ignore_settings', ini='Ignore', cli=None)
    sections: FrozenSet = frozenset({'main', 'report', 'ignore'})
    '''Keys to other CfgKey fields that hold actual lookup values for the related
    internal settings and ini sections.
    Used for introspection with getattr(CfgKey, set_entry).settings and .ini'''

    # configuration storage keys
    scope: SettingKeys = SettingKeys(       settings='attribute_scope',
                                                ini='attribute-scope',
                                                cli='attribute_scope')
    exact: SettingKeys = SettingKeys(       settings='exact_match',
                                                ini='exact-match',
                                                cli='report_exact_match')
    matched: SettingKeys = SettingKeys(     settings='matched',
                                                ini='matched',
                                                cli='report_matched')
    not_imp: SettingKeys = SettingKeys(     settings='not_implemented',
                                                ini='not-implemented',
                                                cli='report_not_implemented')
    extensions: SettingKeys = SettingKeys(  settings='extensions',
                                                ini='extensions',
                                                cli='report_extensions')
    skipped: SettingKeys = SettingKeys(     settings='skipped',
                                                ini='skipped',
                                                cli='report_skipped')
    builtin: SettingKeys = SettingKeys(     settings='use_builtin',
                                                ini='builtin-filter',
                                                cli='use_builtin_filters')
    global_attr: SettingKeys = SettingKeys( settings='global_attributes',
                                                ini='global-attributes',
                                                cli='ignore_global_attributes')
    module_attr: SettingKeys = SettingKeys( settings='module_attributes',
                                                ini='module-attributes',
                                                cli='ignore_module_attributes')
    class_attr: SettingKeys = SettingKeys(  settings='class_attributes',
                                                ini='class-attributes',
                                                cli='ignore_class_attributes')
    docstring: SettingKeys = SettingKeys(   settings='docstring',
                                                ini='docstring',
                                                cli='ignore_docstring')
    annotation: SettingKeys = SettingKeys(  settings='added_annotation',
                                                ini='added-annotation',
                                                cli='ignore_added_annotations')
    '''Above attributes associate internal configuration settings with ini file entries
    and command line arguments'''

    #<section>_<type>: FrozenSet = frozenset({})
    main_options: FrozenSet = frozenset({'scope'})
    # main_bools: FrozenSet = frozenset({})  # placeholder
    # main_sets: FrozenSet = frozenset({})  # placeholder
    # report_options: FrozenSet = frozenset({})  # placeholder
    report_bools: FrozenSet = frozenset({'exact', 'matched', 'not_imp', 'extensions', 'skipped'})
    # report_sets: FrozenSet = frozenset({})  # placeholder
    # ignore_options: FrozenSet = frozenset({})  # placeholder
    ignore_bools: FrozenSet = frozenset({'builtin'})
    ignore_sets: FrozenSet = frozenset(
        {'global_attr', 'module_attr', 'class_attr', 'docstring', 'annotation'})
    '''SettingsKeys Attribute names grouped by section and needed processing.
    Every CfgKey field in the configuration storage keys block should be referenced
    exactly once in the above frozen sets.
    Used for introspection using getattr(CfgKey, set_entry)
    Found by introspection by building the field name from «section»_«processing». 'section'
    is each entry in CfgKey.sections, 'processing is each entry in CfgKey.processing_types.
    '''

    processing_types: FrozenSet = frozenset(
        {Part.option_type, Part.bool_type, Part.set_type})
    '''processing category types. Each of these can have an (optional) entry in CfgKey for
    each configuration section.
    #<section>_<type>: FrozenSet = frozenset({})
    The entries here drive the processing to be done when saving configuration file and
    command line argument values to the corresponding internal application configuration
    setting.
    Used by introspection using getattr(CfgKey, section_name + Part.joiner + entry)
    '''

    # <storage_key><validation_type>: FrozenSet = frozenset({})
    scope_choices: FrozenSet = frozenset({'all', 'public', 'published'})
    '''valid choices for each configuration function (storage key) that must have
    one of a fixed set of values'''
    docstring_contexts: FrozenSet = frozenset({'module', 'class', 'method'})
    annotation_contexts: FrozenSet = frozenset({'parameter', 'return', 'scope'})
    '''keywords for each configuration function (storage key) that can be set to 'all', or
    to a comma-separated list of keywords. Each keyword can be negated by prefixing with
    CfgKey.remove_prefix'''
    negation_prefix: str = 'no'
    '''The prefix to use to reverse the sense of boolean cli arguments'''
    remove_prefix: str = 'no-'
    '''The prefix to use to undo or remove a keyword element from a set'''

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
        self._apply_settings_to_configuration()
        print(self._configuration_settings)  # DEBUG

    def _builtin_attribute_name_exclusions(self) -> Dict[str, FrozenSet[str]]:
        """The built in attribute names to be ignored"""
        builtin_exclusions = {
            CfgKey.global_attr.settings: frozenset(),
            CfgKey.module_attr.settings: frozenset({
                '__builtins__', '__cached__', '__file__', '__package__'}),
            CfgKey.class_attr.settings: frozenset(),
        }
        return copy.deepcopy(builtin_exclusions)

    def _apply_settings_to_configuration(self) -> None:
        """
        Do any processing needed to finalize the application runtime settings from
        loaded configuration file information and command line arguments.

        Merge the builtin exclusions into the active configuration settings
        """
        if self._configuration_settings[CfgKey.ignore.settings][CfgKey.builtin.settings]:
            # The builtin exclusions have not been suppressed
            attribute_exclusions = self._builtin_attribute_name_exclusions()
            for key, value in attribute_exclusions.items():
                target: set = self._configuration_settings[CfgKey.ignore.settings][key]
                target.update(value)

    def _default_configuration(self) -> ConfigurationType:
        """The builtin base (default) configuration settings"""
        def_cfg: Dict[str, ConfigurationType] = {
            CfgKey.report.settings: {
                CfgKey.exact.settings: False,
                CfgKey.matched.settings: False,
                CfgKey.not_imp.settings: False,
                CfgKey.extensions.settings: False,
                CfgKey.skipped.settings: False,
            },
            CfgKey.ignore.settings: {
                CfgKey.builtin.settings: True,
                CfgKey.global_attr.settings: set(),
                CfgKey.module_attr.settings: set(),
                CfgKey.class_attr.settings: set(),
                CfgKey.docstring.settings: set(),
                CfgKey.annotation.settings: set(),
            },
            CfgKey.scope.settings: "all",
        }
        return copy.deepcopy(def_cfg)

    def output_default_ini(self) -> None:
        """
        Output (to standard output) the default application configuration file with
        embedded documentation.
        """
        # pylint:disable=line-too-long
        def_reference = self._default_configuration()
        ini_details: IniStructureType = {
            CfgKey.main.ini: {
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
                    CfgKey.scope.settings: {
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
reverse case will be reported as an extension in the port implementation.''',
                        IniStr.default: def_reference[CfgKey.scope.settings],
                        IniStr.comment: 'choose one of: all, public, published'
                    }
                }
            },
            CfgKey.report.ini: {
                IniStr.description: '''Report configuration section controls what parts of the comparison result are
included in the final report.''',
                IniStr.settings: {
                    CfgKey.exact.settings: {
                        IniStr.doc: '''Include attribute names with exactly matching signatures in the match
differences report.''',
                        IniStr.default: str(def_reference[CfgKey.report.settings][CfgKey.exact.settings]),
                        IniStr.comment: "boolean: True or False"
                    },
                    CfgKey.matched.settings: {
                        IniStr.doc: '''Include report section for attributes with matching names but differing
signatures.''',
                        IniStr.default: str(def_reference[CfgKey.report.settings][CfgKey.matched.settings]),
                        IniStr.comment: "boolean: True or False"
                    },
                    CfgKey.not_imp.settings: {
                        IniStr.doc: "Include report section for attributes not implemented in the port module.",
                        IniStr.default: str(def_reference[CfgKey.report.settings][CfgKey.not_imp.settings]),
                        IniStr.comment: "boolean: True or False"
                    },
                    CfgKey.extensions.settings: {
                        IniStr.doc: '''Include report section for attributes implemented in the port
implementation but not in the base.''',
                        IniStr.default: str(def_reference[CfgKey.report.settings][CfgKey.extensions.settings]),
                        IniStr.comment: "boolean: True or False"
                    },
                    CfgKey.skipped.settings: {
                        IniStr.doc: "Include report section for attribute names that were skipped during the comparison.",
                        IniStr.default: str(def_reference[CfgKey.report.settings][CfgKey.skipped.settings]),
                        IniStr.comment: "boolean: True or False"
                    },
                }
            },
            CfgKey.ignore.ini: {
                IniStr.description: f'''Ignore configuration section allows specifying attribute names or aspects to be
ignored during comparison.

For the entries that allow 'contexts' to be specified, 'all' enables all valid
contexts. To disable a context (possibly previously enable by a different
configuration file), prefix the context with '{CfgKey.remove_prefix}'. The general format is:
all or [{CfgKey.remove_prefix}]<context1>[,[{CfgKey.remove_prefix}]<context2>]...''',
                IniStr.settings: {
                    CfgKey.builtin.settings: {
                        IniStr.doc: '''Include the application builtin attribute names in the context specific
exclusions (common across many modules).''',
                        IniStr.default: str(def_reference[CfgKey.ignore.settings][CfgKey.builtin.settings]),
                        IniStr.comment: "boolean: True or False"
                    },
                    CfgKey.global_attr.settings: {
                        IniStr.doc: "Comma-separated list of attribute names to ignore in all contexts.",
                        IniStr.default: ','.join(def_reference[CfgKey.ignore.settings][CfgKey.global_attr.settings]),
                        IniStr.comment: "list of attribute names"
                    },
                    CfgKey.module_attr.settings: {
                        IniStr.doc: "Comma-separated list of attribute names to ignore when processing an module.",
                        IniStr.default: ','.join(def_reference[CfgKey.ignore.settings][CfgKey.module_attr.settings]),
                        IniStr.comment: "list of attribute names"
                    },
                    CfgKey.class_attr.settings: {
                        IniStr.doc: "Comma-separated list of attribute names to ignore when processing a class.",
                        IniStr.default: ','.join(def_reference[CfgKey.ignore.settings][CfgKey.class_attr.settings]),
                        IniStr.comment: "list of attribute names"
                    },
                    CfgKey.docstring.settings: {
                        IniStr.doc: ''''all' or a comma-separated list of contexts to ignore differences in docstring
values.''',
                        IniStr.default: ','.join(def_reference[CfgKey.ignore.settings][CfgKey.docstring.settings]),
                        IniStr.comment: "contexts: module, class, method"
                    },
                    CfgKey.annotation.settings: {
                        IniStr.doc: ''''all' or a comma-separated list of contexts to ignore annotations that exist
in the port implementation where none was defined for base. These are all
related to method (or function) signatures.
- method parameter typehint
- method return value typehint
- scope is for any entry in the parent class __annotation__ dictionary''',
                        IniStr.default: ','.join(def_reference[CfgKey.ignore.settings][CfgKey.annotation.settings]),
                        IniStr.comment: "contexts: parameter, return, scope"
                    },
                }
            },
        }
        generate_ini_file(sys.stdout, ini_details)

    def _create_command_line_parser(self) -> argparse.ArgumentParser:
        """Creates parser for command-line arguments to configure the application."""
        # pylint:disable=line-too-long
        parser = argparse.ArgumentParser(description='Compare module APIs.')
        parser.add_argument('--version', action='version', version='%(prog)s 0.0.1')
        parser.add_argument('--create-config', action=RunAndExitAction, nargs=0,
                            external_method=self.output_default_ini,
                            help='Create a configuration file with default settings and exit')

        parser.add_argument('--attribute-scope', choices=['all', 'public', 'published'],
                            help='Scope of attributes to compare.')
        add_tri_state_argument(parser, '--report-exact-match',
                               'Include attributes with exact matches in report.',
                               CfgKey.negation_prefix)
        add_tri_state_argument(parser, '--use-builtin-filters',
                               'Include builtin attribute names in context exclusions.',
                               CfgKey.negation_prefix)
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
        parser.add_argument(
            '--ignore-docstring', metavar='CONTEXTS',
            type=make_all_or_keys_validator(CfgKey.docstring_contexts, negation=CfgKey.remove_prefix),
            help="Specify contexts to ignore docstring changes in: 'all' or comma-separated list "
            f"of contexts {{{', '.join(CfgKey.docstring_contexts)}}}. Use '{CfgKey.remove_prefix}<context>' to exclude (not ignore). "
            'Surround list with quotes if spaces included after commas.')
        parser.add_argument(
            '--ignore-added-annotations', metavar='CONTEXTS',
            type=make_all_or_keys_validator(CfgKey.annotation_contexts, negation=CfgKey.remove_prefix),
            help="Specify contexts to ignore added annotations: 'all' or comma-separated list of "
            f"contexts {{{', '.join(CfgKey.annotation_contexts)}}}. Use '{CfgKey.remove_prefix}<context>' to exclude (not ignore). "
            'Surround list with quotes if spaces included after commas.')
        add_tri_state_argument(parser, '--report-matched',
                               'Generate report for differences in matched attributes.',
                               CfgKey.negation_prefix)
        add_tri_state_argument(parser, '--report-not-implemented',
                               'Generate report for attributes not implemented in the port.',
                               CfgKey.negation_prefix)
        add_tri_state_argument(parser, '--report-extensions',
                               'Generate report for extensions implemented in the port.',
                               CfgKey.negation_prefix)
        add_tri_state_argument(parser, '--report-skipped',
                               'Generate report for attributes that were skipped.',
                               CfgKey.negation_prefix)

        # Configuration file arguments
        parser.add_argument('--config-file', action='append',
                            help='Specify a configuration file to load.')
        parser.add_argument('--no-user-config', action='store_false',
                            help='Do not load the user configuration file.')
        parser.add_argument('--no-project-config', action='store_false',
                            help='Do not load the project configuration file.')

        parser.add_argument('base-module-path', metavar='BASE', type=validate_module_path,
            help='Dot notation path for the base module (e.g., "os.path").')

        parser.add_argument('port-module-path', metavar='PORT' ,type=validate_module_path,
            help='Dot notation path for the port module (e.g., "mypackage.mymodule").')

        return parser

    def process_configuration_files(self):
        """Handles command-line arguments related to configuration files."""
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

        See Also:
            CfgKey for values and usage of the referenced entries.
            output_default_ini for information about ini entries.
        """
        config: configparser.ConfigParser = get_config_file(file_path)
        if config is None:
            return False

        for group_name in CfgKey.sections:
            section_keys: SettingKeys = getattr(CfgKey, group_name)
            if section_keys.ini not in config.sections():
                continue

            config_section: configparser.SectionProxy = config[section_keys.ini]
            settings_group: dict = self._configuration_settings if section_keys.settings is None \
                else self._configuration_settings[section_keys.settings]
            for p_type in CfgKey.processing_types:
                for entry in getattr(CfgKey, group_name + Part.joiner + p_type, []):
                    # default '[]' value above allows easy skipping of processing sets that
                    # do not exist
                    self._process_config_case(config_section, settings_group, p_type, entry,
                                              file_path)

        logging.info('settings loaded from "%s"', file_path)
        return True

    def _process_config_case(self, section: configparser.SectionProxy, settings: dict,  # pylint:disable=too-many-arguments
                             processing: str, entry: str, file_path: Path) -> None:
        """
        Processes a single configuration (ini) file entry and updates the associated application
        setting accordingly.

        Args:
            section (SectionProxy): The current INI file section being processed.
            settings (dict): Application settings that correspond to the section.
            processing (str): The type of processing needed for the configuration entry.
            entry (str): The key (name) for current configuration setting being processed.
            file_path (Path): The path to the configuration file being processed, used for logging.
        """
        entry_keys: SettingKeys = getattr(CfgKey, entry)
        ini_value: str = section.get(entry_keys.ini, fallback=SentinelTag(Tag.no_entry))
        if not (ini_value and ini_value is not SentinelTag(Tag.no_entry)):
            return

        if processing == Part.option_type:
            _update_option_from_string(ini_value, settings, entry, file_path=file_path)
        elif processing == Part.bool_type:
            settings[entry_keys.settings] = section.getboolean(entry_keys.ini)
        else:  # processing == Part.set_type
            _update_set_from_string(ini_value, settings[entry_keys.settings], entry,
                                    file_path=file_path)

    def apply_command_line_arguments_to_configuration(self):
        """
        Merge settings from command line arguments

        Args:
            file_path (Path) the path to the configuration file

        See Also:
            CfgKey for values and usage of the referenced entries.
            output_default_ini for information about ini entries.
        """
        for group_name in CfgKey.sections:
            section_keys: SettingKeys = getattr(CfgKey, group_name)
            settings_group: dict = self._configuration_settings if section_keys.settings is None \
                else self._configuration_settings[section_keys.settings]
            for p_type in CfgKey.processing_types:
                for entry in getattr(CfgKey, group_name + Part.joiner + p_type, []):
                    # default '[]' value above allows easy skipping of processing sets that
                    # do not exist
                    self._get_cli_setting(settings_group, p_type, entry)

    def _get_cli_setting(self, settings: dict, processing: str, entry: str) -> None:
        """
        Update a single internal setting from the matching command line argument.

        Args:
            settings (dict): Application settings group.
            processing (str): The type of processing needed for the settings entry.
            entry (str): The key (name) for current configuration setting being processed.
        """
        entry_keys: SettingKeys = getattr(CfgKey, entry)
        cli_value = getattr(self._raw_args, entry_keys.cli)
        if cli_value is None:
            return  # argument was not specified on the command line

        if processing == Part.option_type:
            assert isinstance(cli_value, str), \
                f'found {type(cli_value).__name__} for CLI {entry_keys.cli} ' \
                'argument: expecting str'
            settings[entry_keys.settings] = cli_value
        elif processing == Part.bool_type:
            assert isinstance(cli_value, bool), \
                f'found {type(cli_value).__name__} for CLI {entry_keys.cli} ' \
                'argument: expecting bool'
            settings[entry_keys.settings] = cli_value
        else:  # processing == Part.set_type
            good_set: FrozenSet[str] = getattr(CfgKey, entry + Part.joiner + Part.context,
                                                SentinelTag(Tag.no_entry))
            target: set = settings[entry_keys.settings]
            if good_set is SentinelTag(Tag.no_entry):
                assert isinstance(cli_value, set), \
                    f'found {type(cli_value).__name__} for CLI {entry_keys.cli} ' \
                    'argument: expecting set'
                target.update(cli_value)
            else:
                assert isinstance(cli_value, dict), \
                    f'found {type(cli_value).__name__} for CLI {entry_keys.cli} ' \
                    'argument: expecting dict'
                update_set_keywords_from_dict(target, cli_value)

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

def _update_option_from_string(ini_value: str, settings: Dict[str, str], entry: str,
                               file_path: Path) -> None:
    """
    Updates a settings option from a string.

    Args:
        ini_value (str): The value read from a configuration file
        settings (dict): Application settings block that store the specific setting.
        entry (str): The key (name) for the current configuration setting being processed.
        file_path (Path): The path to the configuration file being processed, used for logging.
    """
    # get the valid choices for 'entry'
    keys_source: SettingKeys = getattr(CfgKey, entry)
    allowed_options: FrozenSet[str] = getattr(CfgKey, entry + Part.joiner + Part.choice)
    if ini_value in allowed_options:
        settings[keys_source.settings] = ini_value
    else:
        logging.error(
            'Invalid %s value "%s" found in "%s". Valid values are: %s',
            keys_source.ini, ini_value, file_path, ', '.join(allowed_options))

def _update_set_from_string(ini_value: str, target: Set[str], entry: str, **kwargs) -> None:
    """
    Updates (configuration) set based on a string from a configuration file entry.

    Args:
        ini_value (str): The value read from a configuration file
        target (Set[str]): The settings entry to be updated
        entry (str): The key (name) for the current configuration setting being processed.
        kwargs: pass arguments through to low level methods to enhance error logging.
                specifically source_entry and file_path for process_keyword_settings
    """
    # get the base keywords allowed for 'entry' (if it is a keywords attribute)
    good_set: FrozenSet[str] = getattr(CfgKey, entry + Part.joiner + Part.context,
                                        SentinelTag(Tag.no_entry))
    if good_set is SentinelTag(Tag.no_entry):
        # no keyword validation set: everything else is attribute names
        target.update(validate_attribute_names(ini_value))
    else:
        update_set_keywords_from_string(target, ini_value, good_set,
            remove_prefix=CfgKey.remove_prefix, source_entry=getattr(CfgKey, entry).ini, **kwargs)

if __name__ == "__main__":
    app = CompareModuleAPI()

# pylint:disable=line-too-long
# cSpell:words configparser pathlib expanduser getboolean posix getint getfloat metavar issubset docstrings dunder
# cSpell:ignore nargs appdata mypackage
# cSpell:allowCompoundWords true
