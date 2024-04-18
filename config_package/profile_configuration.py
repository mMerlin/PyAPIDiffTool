# SPDX-FileCopyrightText: 2024 H Phil Duby
# SPDX-License-Identifier: MIT

"""
`manage configuration for comparing module interfaces`
==================

Load configuration (ini) file content and command line argument data
creating validated configuration settings.
"""

import argparse
from collections import namedtuple
import configparser
import copy
from dataclasses import dataclass, field
from enum import Enum, auto
import logging
from pathlib import Path
import sys
from typing import Union, Dict, Any, FrozenSet, Set

from generic_tools import (
    SentinelTag, RunAndExitAction, IniStr, IniStructureType,
    add_tri_state_argument, validate_module_path, make_all_or_keys_validator,
    attribute_names_validator, get_config_path, get_config_file, update_set_keywords_from_string,
    update_set_keywords_from_dict, validate_attribute_names, generate_ini_file
)

ConfigurationType = Union[bool, str, set, Dict[str, Any]]

@dataclass(frozen=True)
class CfgFld:
    """Constants for names of ProfileCOnfiguration fields, to be able to use named constants
    instead of literal value when referencing the __dict__ fields."""
    # pylint:disable=too-many-instance-attributes
    base: str = 'base'
    port: str = 'port'
    scope: str = 'scope'
    logging_level: str = 'logging_level'
    skip_attributes_global: str = 'skip_attributes_global'
    skip_attributes_module: str = 'skip_attributes_module'
    skip_attributes_class: str = 'skip_attributes_class'
    docstring_ignore_module: str = 'docstring_ignore_module'
    docstring_ignore_class: str = 'docstring_ignore_class'
    docstring_ignore_method: str = 'docstring_ignore_method'
    annotation_ignore_scope: str = 'annotation_ignore_scope'
    annotation_ignore_parameter: str = 'annotation_ignore_parameter'
    annotation_ignore_return: str = 'annotation_ignore_return'
    # use_builtin: str = 'use_builtin'
    report_matched: str = 'report_matched'
    report_exact: str = 'report_exact'
    report_not_implemented: str = 'report_not_implemented'
    report_extensions: str = 'report_extensions'
    report_skipped: str = 'report_skipped'

@dataclass(frozen=True)
class IniKey:
    """
    keys for configuration (ini) file entries.
    """
    main: str = 'Main'
    report: str = 'Report'
    ignore: str = 'Ignore'
    sections: FrozenSet = frozenset({'main', 'report', 'ignore'})
    '''Keys to other IniKey fields that hold actual lookup values for the related ini sections.
    Used for introspection with getattr(IniKey, set_entry)'''

@dataclass(frozen=True)
class Part:
    """
    parts of configuration key attribute (field) names
    """
    # pylint:disable=too-many-instance-attributes
    option_type: str = 'options'
    bool_type: str = 'bools'
    set_type: str = 'sets'
    choice: str = 'choices'
    context: str = 'contexts'
    joiner: str = '_'
    negation_prefix: str = 'no'
    '''The prefix to use to reverse the sense of boolean cli arguments'''
    remove_prefix: str = 'no-'
    '''The prefix to use to undo or remove a keyword element from a set'''

@dataclass(frozen=True)
class PrcKey:
    """
    keys for processing configuration information.
    """
    processing_types: FrozenSet = frozenset(
        {Part.option_type, Part.bool_type, Part.set_type})
    '''processing category types. Each of these can have an (optional) entry in PrcKey for
    each configuration section.
    #<section>_<type>: FrozenSet = frozenset({})
    The entries there drive the processing to be done when saving configuration file and
    command line argument values to the corresponding internal application configuration
    setting.
    Used by introspection using getattr(PrcKey, section_name + Part.joiner + entry)
    '''

    #<section>_<type>: FrozenSet = frozenset({})
    main_options: FrozenSet = frozenset({'scope', 'loglevel'})
    # main_bools: FrozenSet = frozenset({})  # placeholder
    # main_sets: FrozenSet = frozenset({})  # placeholder
    # report_options: FrozenSet = frozenset({})  # placeholder
    report_bools: FrozenSet = frozenset({'exact', 'matched', 'not_imp', 'extensions', 'skipped'})
    # report_sets: FrozenSet = frozenset({})  # placeholder
    # ignore_options: FrozenSet = frozenset({})  # placeholder
    ignore_bools: FrozenSet = frozenset({'builtin'})
    ignore_sets: FrozenSet = frozenset(
        {'global_attr', 'module_attr', 'class_attr', 'docstring', 'annotation'})
    '''SettingsKeys attribute names grouped by section and needed processing.
    Every CfgKey field in the configuration storage keys block should be referenced
    exactly once in the above frozen sets.
    Used for introspection using getattr(PrcKey, set_entry)
    Found by introspection by building the field name from «section»_«processing». 'section'
    is each entry in IniKey.sections, 'processing is each entry in PrcKey.processing_types.
    '''

class Setting(Enum):
    """settings that can be accessed from internal configuration"""
    SCOPE = auto()
    LOGGING_LEVEL = auto()
    REPORT_EXACT_MATCH = auto()
    REPORT_MATCHED = auto()
    REPORT_NOT_IMPLEMENTED = auto()
    REPORT_EXTENSION = auto()
    REPORT_SKIPPED = auto()
    USE_BUILTIN = auto()
    IGNORE_MODULE_ATTRIBUTES = auto()
    IGNORE_GLOBAL_ATTRIBUTES = auto()
    IGNORE_CLASS_ATTRIBUTES = auto()
    IGNORE_DOCSTRING = auto()
    IGNORE_ADDED_ANNOTATION = auto()

SettingKeys = namedtuple('SettingKeys', ['settings', 'ini', 'cli'])
'''
Keys (str) to access settings information in different contexts
settings: the internal configuration dictionary key
ini: the key in an ini configuration file
cli: the key to parsed command line argument information
'''

@dataclass(frozen=True)
class SetKey:
    """
    Constants for set entries for settings that can have multiple (concurrent) values
    """
    # pylint:disable=too-many-instance-attributes
    all: str = 'all'
    public: str = 'public'
    published: str = 'published'
    debug: str = 'DEBUG'
    info: str = 'INFO'
    warning: str = 'WARNING'
    error: str = 'ERROR'
    critical: str = 'CRITICAL'
    module: str = 'module'
    class_key: str = 'class'
    method: str = 'method'
    parameter: str = 'parameter'
    return_key: str = 'return'
    scope: str = 'scope'

@dataclass(frozen=True)
class Tag:
    """
    keys for SentinelTag instances.
    """
    no_entry: str = 'No entry exists'

# Uses Settings and SettingKeys: define after other supporting classes
@dataclass(frozen=True)
class CfgKey:
    """
    keys for configuration setting entries.
    """
    # pylint:disable=too-many-instance-attributes

    # configuration storage keys
    scope: SettingKeys = SettingKeys(       settings=Setting.SCOPE.name,
                                                ini='attribute-scope',
                                                cli='attribute_scope')
    loglevel: SettingKeys = SettingKeys(    settings=Setting.LOGGING_LEVEL.name,
                                                ini='logging-level',
                                                cli='logging_level')
    exact: SettingKeys = SettingKeys(       settings=Setting.REPORT_EXACT_MATCH.name,
                                                ini='exact-match',
                                                cli='report_exact_match')
    matched: SettingKeys = SettingKeys(     settings=Setting.REPORT_MATCHED.name,
                                                ini='matched',
                                                cli='report_matched')
    not_imp: SettingKeys = SettingKeys(     settings=Setting.REPORT_NOT_IMPLEMENTED.name,
                                                ini='not-implemented',
                                                cli='report_not_implemented')
    extensions: SettingKeys = SettingKeys(  settings=Setting.REPORT_EXTENSION.name,
                                                ini='extensions',
                                                cli='report_extensions')
    skipped: SettingKeys = SettingKeys(     settings=Setting.REPORT_SKIPPED.name,
                                                ini='skipped',
                                                cli='report_skipped')
    builtin: SettingKeys = SettingKeys(     settings=Setting.USE_BUILTIN.name,
                                                ini='builtin-filter',
                                                cli='use_builtin_filters')
    global_attr: SettingKeys = SettingKeys( settings=Setting.IGNORE_GLOBAL_ATTRIBUTES.name,
                                                ini='global-attributes',
                                                cli='ignore_global_attributes')
    module_attr: SettingKeys = SettingKeys( settings=Setting.IGNORE_MODULE_ATTRIBUTES.name,
                                                ini='module-attributes',
                                                cli='ignore_module_attributes')
    class_attr: SettingKeys = SettingKeys(  settings=Setting.IGNORE_CLASS_ATTRIBUTES.name,
                                                ini='class-attributes',
                                                cli='ignore_class_attributes')
    docstring: SettingKeys = SettingKeys(   settings=Setting.IGNORE_DOCSTRING.name,
                                                ini='docstring',
                                                cli='ignore_docstring')
    annotation: SettingKeys = SettingKeys(  settings=Setting.IGNORE_ADDED_ANNOTATION.name,
                                                ini='added-annotation',
                                                cli='ignore_added_annotations')
    '''Above attributes associate internal configuration settings with ini file entries
    and command line arguments'''

    # <storage_key>_<validation_type>: FrozenSet = frozenset({})
    scope_choices: FrozenSet = frozenset({SetKey.all, SetKey.public, SetKey.published})
    loglevel_choices: FrozenSet = frozenset({SetKey.debug, SetKey.info, SetKey.warning,
                                             SetKey.error, SetKey.critical})
    '''valid choices for each configuration function (storage key) that must have
    one of a fixed set of values'''
    docstring_contexts: FrozenSet = frozenset({SetKey.module, SetKey.class_key, SetKey.method})
    annotation_contexts: FrozenSet = frozenset({SetKey.parameter, SetKey.return_key, SetKey.scope})
    '''keywords for each configuration function (storage key) that can be set to 'all', or
    to a comma-separated list of keywords. Each keyword can be negated by prefixing with
    Part.remove_prefix

    Above attributes are found through introspection using
      getattr(CfgKey, <storage_key> + Part.joiner + <validation>)
    Validation is one of Part.choice or Part.context
    '''

@dataclass(frozen=True)
class ProfileConfiguration:
    """Manages setting configuration information for comparing module apis

    This creates a valid base (default) configuration, loads validated configuration (ini)
    information, loads configuration data from command line arguments, then provides
    access to the immutable settings.

    Attributes:
        _app_name (str): Application name used to look for configuration files.
        _logger (Logger): The Logger instance use for report exception details.
        _configuration_settings (dict): Stores the application's configuration settings
            while collecting.
        see CfgFld
    """
    # pylint:disable=too-many-instance-attributes,no-member
    base: str
    """path to base python module"""
    port: str
    """path to ported python module"""
    scope: str  # CfgKey.scope_choices
    logging_level: str # CfgKey.loglevel_choices
    skip_attributes_global: FrozenSet[str]
    """attribute names to always skip"""
    skip_attributes_module: FrozenSet[str]
    """attribute names skip in a module"""
    skip_attributes_class: FrozenSet[str]
    """attribute names skip in a class"""
    docstring_ignore_module: bool
    """ignore differences in module docstrings"""
    docstring_ignore_class: bool
    """ignore differences in class docstrings"""
    docstring_ignore_method: bool
    """ignore differences in method docstrings"""
    annotation_ignore_scope: bool
    """ignore difference when scope annotation exists in port but not in base"""
    annotation_ignore_parameter: bool
    """ignore difference when parameter annotation exists in port but not in base"""
    annotation_ignore_return: bool
    """ignore difference when return annotation exists in port but not in base"""
    # use_builtin: bool  # only needed internally ?
    # """include builtin attribute name exclusions in ignore sets"""
    report_matched: bool
    """output report of attributes that exist in both base and port implementation"""
    report_exact: bool
    """include exact matches in match report"""
    report_not_implemented: bool
    """output report of attributes that exist in base but not in port implementation"""
    report_extensions: bool
    """output report of attributes that exist in port but not in base implementation"""
    report_skipped: bool
    """output report of attributes that were skipped in port or base implementation"""
    __annotation__: Dict[str, type] = field(
        default_factory=lambda: {
            '_app_name': str,
            '_logger': logging.Logger,
            '_configuration_settings': Dict[str, ConfigurationType],
        },
        repr=False)
    """typehints for private attributes created with object.__setattr__"""

    def __init__(self, application_name: str, logger_name: str = None):
        """
        initialize ProfileConfiguration instance

        Args:
            application_name (str) The name of the application the configuration is for
            logger_name (str) The name of the Logger to use for reporting exception details
        """
        object.__setattr__(self, '_app_name', application_name)
        object.__setattr__(self, '_logger', logging.getLogger(logger_name
            if isinstance(logger_name, str) and logger_name else 'root'))
        if not self._logger.handlers:
            raise TypeError(f'The "{self._logger.name}" logger does not have any handler')
        cli_args: argparse.Namespace = self._get_configuration_settings()

        # Populate the profile configuration fields, and do final validation checks
        self.__dict__[CfgFld.base] = cli_args.base_module_path
        self.__dict__[CfgFld.port] = cli_args.port_module_path
        self.__dict__[CfgFld.scope] = self._configuration_settings[Setting.SCOPE.name]
        self.__dict__[CfgFld.logging_level] = \
            self._configuration_settings[Setting.LOGGING_LEVEL.name]
        self.__dict__[CfgFld.skip_attributes_global] = frozenset(
            self._configuration_settings[Setting.IGNORE_GLOBAL_ATTRIBUTES.name])
        self.__dict__[CfgFld.skip_attributes_module] = frozenset(
            self._configuration_settings[Setting.IGNORE_MODULE_ATTRIBUTES.name])
        self.__dict__[CfgFld.skip_attributes_class] = frozenset(
            self._configuration_settings[Setting.IGNORE_CLASS_ATTRIBUTES.name])
        self.__dict__[CfgFld.docstring_ignore_module] = SetKey.module in \
            self._configuration_settings[Setting.IGNORE_DOCSTRING.name]
        self.__dict__[CfgFld.docstring_ignore_class] = SetKey.class_key in \
            self._configuration_settings[Setting.IGNORE_DOCSTRING.name]
        self.__dict__[CfgFld.docstring_ignore_method] = SetKey.method in \
            self._configuration_settings[Setting.IGNORE_DOCSTRING.name]
        self.__dict__[CfgFld.annotation_ignore_scope] = SetKey.scope in \
            self._configuration_settings[Setting.IGNORE_ADDED_ANNOTATION.name]
        self.__dict__[CfgFld.annotation_ignore_parameter] = SetKey.parameter in \
            self._configuration_settings[Setting.IGNORE_ADDED_ANNOTATION.name]
        self.__dict__[CfgFld.annotation_ignore_return] = SetKey.return_key in \
            self._configuration_settings[Setting.IGNORE_ADDED_ANNOTATION.name]
        # self.__dict__[CfgFld.use_builtin] = self._configuration_settings[Setting.USE_BUILTIN.name]
        self.__dict__[CfgFld.report_matched] = \
            self._configuration_settings[Setting.REPORT_MATCHED.name]
        self.__dict__[CfgFld.report_exact] = \
            self._configuration_settings[Setting.REPORT_EXACT_MATCH.name]
        self.__dict__[CfgFld.report_not_implemented] = \
            self._configuration_settings[Setting.REPORT_NOT_IMPLEMENTED.name]
        self.__dict__[CfgFld.report_extensions] = \
            self._configuration_settings[Setting.REPORT_EXTENSION.name]
        self.__dict__[CfgFld.report_skipped] = \
            self._configuration_settings[Setting.REPORT_SKIPPED.name]
        if self.scope not in CfgKey.scope_choices:
            raise ValueError(f'scope {self.scope} is not one of {CfgKey.scope_choices}')
        if self.logging_level not in CfgKey.loglevel_choices:
            raise ValueError(f'logging level {self.scope} is not one of {CfgKey.loglevel_choices}')
        if not isinstance(self.skip_attributes_module, FrozenSet):
            raise ValueError(
                f'module attributes {type(self.skip_attributes_module)} is not FrozenSet')
        if not isinstance(self.skip_attributes_global, FrozenSet):
            raise ValueError(
                f'global attributes {type(self.skip_attributes_global)} is not FrozenSet')
        # All validation for the source information for boolean fields is done as
        # self._configuration_settings is populated.
        self._configuration_settings.clear()

    def _get_configuration_settings(self) -> argparse.Namespace:
        """
        Get the profile configuration settings, cascaded from default values,
        configuration files, and command line arguments.

        Returns
            (argparse.Namespace) containing the command line argument information
        """
        object.__setattr__(self, '_configuration_settings', self._default_configuration())
        self._logger.setLevel(self._configuration_settings[Setting.LOGGING_LEVEL.name])
        cmd_line_parser: argparse.ArgumentParser = self._create_command_line_parser()
        cli_args: argparse.Namespace = cmd_line_parser.parse_args()
        self._logger.setLevel(self._configuration_settings[Setting.LOGGING_LEVEL.name])
        self._process_configuration_files(cli_args)
        self._apply_command_line_arguments_to_configuration(cli_args)
        self._apply_settings_to_configuration()
        return cli_args

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
        if self._configuration_settings[Setting.USE_BUILTIN.name]:
            # The builtin exclusions have not been suppressed
            attribute_exclusions = self._builtin_attribute_name_exclusions()
            for key, value in attribute_exclusions.items():
                target: set = self._configuration_settings[key]
                target.update(value)

    def _default_configuration(self) -> ConfigurationType:
        """The builtin base (default) configuration settings"""
        def_cfg: Dict[str, ConfigurationType] = {
            CfgKey.scope.settings: "all",
            CfgKey.loglevel.settings: logging.getLevelName(logging.WARN),
            CfgKey.exact.settings: False,
            CfgKey.matched.settings: False,
            CfgKey.not_imp.settings: False,
            CfgKey.extensions.settings: False,
            CfgKey.skipped.settings: False,
            CfgKey.builtin.settings: True,
            CfgKey.global_attr.settings: set(),
            CfgKey.module_attr.settings: set(),
            CfgKey.class_attr.settings: set(),
            CfgKey.docstring.settings: set(),
            CfgKey.annotation.settings: set(),
        }
        return def_cfg

    def _output_default_ini(self) -> None:
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
files are loaded in the order the options are specified.

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
                    },
                    CfgKey.loglevel.settings: {
                        IniStr.doc: '''Set the minimum severity level for messages to include in the application
log file.''',
                        IniStr.default: def_reference[CfgKey.loglevel.settings],
                        IniStr.comment: 'choose one of: DEBUG, INFO, WARN, ERROR, CRITICAL'
                    }
                }
            },
            IniKey.report: {
                IniStr.description: '''Report configuration section controls what parts of the comparison result are
included in the final report.''',
                IniStr.settings: {
                    CfgKey.exact.settings: {
                        IniStr.doc: '''Include attribute names with exactly matching signatures in the match
differences report.''',
                        IniStr.default: str(def_reference[CfgKey.exact.settings]),
                        IniStr.comment: "boolean: True or False"
                    },
                    CfgKey.matched.settings: {
                        IniStr.doc: '''Include report section for attributes with matching names but differing
signatures.''',
                        IniStr.default: str(def_reference[CfgKey.matched.settings]),
                        IniStr.comment: "boolean: True or False"
                    },
                    CfgKey.not_imp.settings: {
                        IniStr.doc: "Include report section for attributes not implemented in the port module.",
                        IniStr.default: str(def_reference[CfgKey.not_imp.settings]),
                        IniStr.comment: "boolean: True or False"
                    },
                    CfgKey.extensions.settings: {
                        IniStr.doc: '''Include report section for attributes implemented in the port
implementation but not in the base.''',
                        IniStr.default: str(def_reference[CfgKey.extensions.settings]),
                        IniStr.comment: "boolean: True or False"
                    },
                    CfgKey.skipped.settings: {
                        IniStr.doc: "Include report section for attribute names that were skipped during the comparison.",
                        IniStr.default: str(def_reference[CfgKey.skipped.settings]),
                        IniStr.comment: "boolean: True or False"
                    },
                }
            },
            IniKey.ignore: {
                IniStr.description: f'''Ignore configuration section allows specifying attribute names or aspects to be
ignored during comparison.

For the entries that allow 'contexts' to be specified, 'all' enables all valid
contexts. To disable a context (possibly previously enable by a different
configuration file), prefix the context with '{Part.remove_prefix}'. The general format is:
all or [{Part.remove_prefix}]<context1>[,[{Part.remove_prefix}]<context2>]...''',
                IniStr.settings: {
                    CfgKey.builtin.settings: {
                        IniStr.doc: '''Include the application builtin attribute names in the context specific
exclusions (common across many modules).''',
                        IniStr.default: str(def_reference[CfgKey.builtin.settings]),
                        IniStr.comment: "boolean: True or False"
                    },
                    CfgKey.global_attr.settings: {
                        IniStr.doc: "Comma-separated list of attribute names to ignore in all contexts.",
                        IniStr.default: ','.join(def_reference[CfgKey.global_attr.settings]),
                        IniStr.comment: "list of attribute names"
                    },
                    CfgKey.module_attr.settings: {
                        IniStr.doc: "Comma-separated list of attribute names to ignore when processing an module.",
                        IniStr.default: ','.join(def_reference[CfgKey.module_attr.settings]),
                        IniStr.comment: "list of attribute names"
                    },
                    CfgKey.class_attr.settings: {
                        IniStr.doc: "Comma-separated list of attribute names to ignore when processing a class.",
                        IniStr.default: ','.join(def_reference[CfgKey.class_attr.settings]),
                        IniStr.comment: "list of attribute names"
                    },
                    CfgKey.docstring.settings: {
                        IniStr.doc: ''''all' or a comma-separated list of contexts to ignore differences in docstring
values.''',
                        IniStr.default: ','.join(def_reference[CfgKey.docstring.settings]),
                        IniStr.comment: "contexts: module, class, method"
                    },
                    CfgKey.annotation.settings: {
                        IniStr.doc: ''''all' or a comma-separated list of contexts to ignore annotations that exist
in the port implementation where none was defined for base. These are all
related to method (or function) signatures.
- method parameter typehint
- method return value typehint
- scope is for any entry in the parent class __annotation__ dictionary''',
                        IniStr.default: ','.join(def_reference[CfgKey.annotation.settings]),
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
        parser.add_argument('--generate-rcfile', action=RunAndExitAction, nargs=0,
                            external_method=self._output_default_ini,
                            help='Generate a sample configuration file with default settings and exit')

        parser.add_argument('--attribute-scope', choices=['all', 'public', 'published'],
                            help='Scope of attributes to compare.')
        parser.add_argument('--logging-level', choices=['DEBUG', 'INFO', 'WARN', 'ERROR', 'CRITICAL'],
                            help='Level to start logging at.')
        add_tri_state_argument(parser, '--report-exact-match',
                               'Include attributes with exact matches in report.',
                               Part.negation_prefix)
        add_tri_state_argument(parser, '--use-builtin-filters',
                               'Include builtin attribute names in context exclusions.',
                               Part.negation_prefix)
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
            type=make_all_or_keys_validator(CfgKey.docstring_contexts, negation=Part.remove_prefix),
            help="Specify contexts to ignore docstring changes in: 'all' or comma-separated list "
            f"of contexts {{{', '.join(CfgKey.docstring_contexts)}}}. Use '{Part.remove_prefix}<context>' to exclude (not ignore). "
            'Surround list with quotes if spaces included after commas.')
        parser.add_argument(
            '--ignore-added-annotations', metavar='CONTEXTS',
            type=make_all_or_keys_validator(CfgKey.annotation_contexts, negation=Part.remove_prefix),
            help="Specify contexts to ignore added annotations: 'all' or comma-separated list of "
            f"contexts {{{', '.join(CfgKey.annotation_contexts)}}}. Use '{Part.remove_prefix}<context>' to exclude (not ignore). "
            'Surround list with quotes if spaces included after commas.')
        add_tri_state_argument(parser, '--report-matched',
                               'Generate report for differences in matched attributes.',
                               Part.negation_prefix)
        add_tri_state_argument(parser, '--report-not-implemented',
                               'Generate report for attributes not implemented in the port.',
                               Part.negation_prefix)
        add_tri_state_argument(parser, '--report-extensions',
                               'Generate report for extensions implemented in the port.',
                               Part.negation_prefix)
        add_tri_state_argument(parser, '--report-skipped',
                               'Generate report for attributes that were skipped.',
                               Part.negation_prefix)

        # Configuration file arguments
        parser.add_argument('--config-file', action='append',
                            help='Specify a configuration file to load.')
        parser.add_argument('--no-user-config', action='store_false',
                            help='Do not load the user configuration file.')
        parser.add_argument('--no-project-config', action='store_false',
                            help='Do not load the project configuration file.')

        parser.add_argument('base_module_path', type=validate_module_path,
            help='Dot notation path for the base module (e.g., "os.path").')

        parser.add_argument('port_module_path', type=validate_module_path,
            help='Dot notation path for the port module (e.g., "mypackage.mymodule").')

        return parser

    def _process_configuration_files(self, cli: argparse.Namespace) -> None:
        """
        Handles command-line arguments related to configuration files.

        Args:
            cli (Namespace): parsed command line argument data
        """
        if cli.no_user_config:
            self._load_configuration_file(self._user_config_path())
        if cli.no_project_config:
            self._load_configuration_file(self._project_config_path())
        if cli.config_file:
            for cfg_file in cli.config_file:
                if not self._load_configuration_file(Path(cfg_file)):
                    self._logger.error('configuration file "%s" requested on the command line '
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

        for group_name in IniKey.sections:
            section_key: str = getattr(IniKey, group_name)
            if section_key not in config.sections():
                continue

            config_section: configparser.SectionProxy = config[section_key]
            for p_type in PrcKey.processing_types:
                for entry in getattr(PrcKey, group_name + Part.joiner + p_type, []):
                    # default '[]' value above allows easy skipping of processing sets that
                    # do not exist
                    self._process_config_case(config_section, p_type, entry, file_path)

        self._logger.setLevel(self._configuration_settings[Setting.LOGGING_LEVEL.name])
        self._logger.info('settings loaded from "%s"', file_path)
        return True

    def _process_config_case(self, section: configparser.SectionProxy,
                             processing: str, entry: str, file_path: Path) -> None:
        """
        Processes a single configuration (ini) file entry and updates the associated application
        setting accordingly.

        Args:
            section (SectionProxy): The current INI file section being processed.
            processing (str): The type of processing needed for the configuration entry.
            entry (str): The key (name) for current configuration setting being processed.
            file_path (Path): The path to the configuration file being processed, used for logging.
        """
        entry_keys: SettingKeys = getattr(CfgKey, entry)
        ini_value: str = section.get(entry_keys.ini, fallback=SentinelTag(Tag.no_entry))
        if not (ini_value and ini_value is not SentinelTag(Tag.no_entry)):
            return

        if processing == Part.option_type:
            self._update_option_from_string(ini_value, entry, file_path=file_path)
        elif processing == Part.bool_type:
            self._configuration_settings[entry_keys.settings] = section.getboolean(entry_keys.ini)
        else:  # processing == Part.set_type
            _update_set_from_string(ini_value, self._configuration_settings[entry_keys.settings],
                                    entry, file_path=file_path)

    def _apply_command_line_arguments_to_configuration(self, cli: argparse.Namespace) -> None:
        """
        Merge settings from command line arguments

        Args:
            cli (Namespace): parsed command line argument data
            file_path (Path) the path to the configuration file

        See Also:
            CfgKey for values and usage of the referenced entries.
            output_default_ini for information about ini entries.
        """
        for group_name in IniKey.sections:
            for p_type in PrcKey.processing_types:
                for entry in getattr(CfgKey, group_name + Part.joiner + p_type, []):
                    # default '[]' value above allows easy skipping of processing sets that
                    # do not exist
                    self._get_cli_setting(cli, p_type, entry)

    def _get_cli_setting(self, cli: argparse.Namespace, processing: str, entry: str) -> None:
        """
        Update a single internal setting from the matching command line argument.

        Args:
            cli (Namespace): parsed command line argument data
            processing (str): The type of processing needed for the settings entry.
            entry (str): The key (name) for current configuration setting being processed.
        """
        entry_keys: SettingKeys = getattr(CfgKey, entry)
        cli_value = getattr(cli, entry_keys.cli)
        if cli_value is None:
            return  # argument was not specified on the command line

        if processing == Part.option_type:
            assert isinstance(cli_value, str), \
                f'found {type(cli_value).__name__} for CLI {entry_keys.cli} ' \
                'argument: expecting str'
            self._configuration_settings[entry_keys.settings] = cli_value
        elif processing == Part.bool_type:
            assert isinstance(cli_value, bool), \
                f'found {type(cli_value).__name__} for CLI {entry_keys.cli} ' \
                'argument: expecting bool'
            self._configuration_settings[entry_keys.settings] = cli_value
        else:  # processing == Part.set_type
            good_set: FrozenSet[str] = getattr(CfgKey, entry + Part.joiner + Part.context,
                                                SentinelTag(Tag.no_entry))
            target: set = self._configuration_settings[entry_keys.settings]
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
        return get_config_path(self._app_name) / f'{self._app_name}.ini'

    def _project_config_path(self) -> Path:
        """
        get the path to the project configuration file

        returns (str) the path to the project application configuration file
        """
        return Path.cwd() / f'{self._app_name}.ini'

    def _update_option_from_string(self, ini_value: str, entry: str, file_path: Path) -> None:
        """
        Updates a settings option from a string.

        Args:
            ini_value (str): The value read from a configuration file
            entry (str): The key (name) for the current configuration setting being processed.
            file_path (Path): The path to the configuration file being processed, used for logging.
        """
        # get the valid choices for 'entry'
        keys_source: SettingKeys = getattr(CfgKey, entry)
        allowed_options: FrozenSet[str] = getattr(CfgKey, entry + Part.joiner + Part.choice)
        if ini_value in allowed_options:
            self._configuration_settings[keys_source.settings] = ini_value
        else:
            self._logger.error(
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
            remove_prefix=Part.remove_prefix, source_entry=getattr(CfgKey, entry).ini, **kwargs)

if __name__ == "__main__":
    app = ProfileConfiguration('TestAppConfig')

# pylint:disable=line-too-long
# cSpell:words configparser pathlib expanduser getboolean posix getint getfloat metavar issubset docstrings dunder typehints
# cSpell:ignore nargs appdata mypackage rcfile
# cSpell:allowCompoundWords true
