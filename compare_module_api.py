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
class IniKey:
    """
    keys for configuration (ini) file entries.
    """
    # pylint:disable=too-many-instance-attributes
    main: str = 'Main'
    report: str = 'Report'
    ignore: str = 'Ignore'
    '''ini file section names'''
    sections: FrozenSet = frozenset({'main', 'report', 'ignore'})
    '''keys to IniKey and CfgKey attributes that hold actual lookup values for to related
    ini sections to internal application configuration data. Each entry in IniKey.sections
    needs matching entries in both IniKey and CfgKey. ie.
    'main' ==> IniKey.main and CfgKey.main
    Used for introspection using getattr(IniKey, entry) and getattr(CfgKey, entry'''

    # configuration entry keys
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
    '''Above attributes need corresponding entries in CfgKey containing keys to associated
    configuration settings in the CompareModuleAPI instance ._configuration_settings
    dictionary.'''

@dataclass(frozen=True)
class CfgKey:
    """
    keys for configuration setting entries.
    """
    # pylint:disable=too-many-instance-attributes
    main: str = None
    report: str = 'report_settings'
    ignore: str = 'ignore_settings'
    '''application configuration data block references. Keys into CompareModuleAPI
    instance ._configuration_settings dictionary. None is the dictionary itself.
    These correspond to entries in IniKey.sections'''

    # configuration storage keys
    scope: str = 'attribute_scope'
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
    '''Above attributes need corresponding entries in IniKey containing keys to associated
    ini configuration file entries.'''

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
    '''Attribute names from both IniKey and CfgKey grouped by section and needed processing.
    Every entry in the 'configuration storage keys' block of attributes should be referenced
    exactly once in the above frozen sets.
    Used for introspection using getattr(CfgKey, entry)'''

    processing_types: FrozenSet = frozenset(
        {Part.option_type, Part.bool_type, Part.set_type})
    '''processing category types. Each of these can have an (optional) entry in CfgKey for
    each configuration section.
    #<section>_<type>: FrozenSet = frozenset({})
    The entries here drive the processing to be done when saving configuration file values to
    the corresponding internal application configuration setting.
    Used for introspection using getattr(CfgKey, section_name + entry)
    '''

    # <storage_key><validation_type>: FrozenSet = frozenset({})
    scope_choices: FrozenSet = frozenset({'all', 'public', 'published'})
    '''valid choices for each configuration function (storage key) that must have
    one of a fixed set of values'''
    docstring_contexts: FrozenSet = frozenset({'module', 'class', 'method'})
    annotation_contexts: FrozenSet = frozenset({'parameter', 'return', 'scope'})
    '''keywords for each configuration function (storage key) that can be set to 'all', or
    to a comma-separated list of keywords. Each keyword can be negated by prefixing with
    CfgKey.negation_prefix'''
    negation_prefix: str = 'no-'
    '''The prefix to use to reverse the sense of keyword parameters'''

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

        See Also:
            IniKey and CfgKey for values and usage of the referenced entries.
            output_default_ini for information about ini entries.
        """
        config: configparser.ConfigParser = get_config_file(file_path)
        if config is None:
            return False

        for section_name in IniKey.sections:
            section_key: str = getattr(IniKey, section_name)
            if section_key not in config.sections():
                continue

            section: configparser.SectionProxy = config[section_key]
            settings_key: str = getattr(CfgKey, section_name)
            settings_group: dict = self._configuration_settings if settings_key is None \
                else self._configuration_settings[settings_key]
            for p_type in CfgKey.processing_types:
                for entry in getattr(CfgKey, section_name + Part.joiner + p_type, []):
                    self._process_config_case(section, settings_group, p_type, entry,
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
            entry (str): The key for current configuration setting being processed. This
                    corresponds to a field (name) in both IniKey and CfgKey, which in turn
                    are ini section entries keys and settings keys.
            file_path (Path): The path to the configuration file being processed, used for logging.
        """
        ini_key: str = getattr(IniKey, entry)
        ini_value: str = section.get(ini_key, fallback=SentinelTag(Tag.no_entry))
        if not (ini_value and ini_value is not SentinelTag(Tag.no_entry)):
            return

        settings_key = getattr(CfgKey, entry)
        if processing == Part.option_type:
            _update_option_from_string(ini_value, settings, settings_key, entry, ini_key, file_path)
        elif processing == Part.bool_type:
            settings[settings_key] = section.getboolean(ini_key)
        else:  # processing == Part.set_type
            _update_set_from_string(ini_value, settings[settings_key], entry, file_path=file_path)

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

def _update_option_from_string(ini_value: str, settings: Dict[str, str], settings_key: str,  # pylint:disable=too-many-arguments
                               entry: str, ini_key: str, file_path: Path) -> None:
    """
    Updates a settings option from a string.

    Args:
        ini_value (str): The value read from a configuration file
        settings (dict): Application settings block that store the specific setting.
        settings_key (str): Key for settings entry to be updated.
        entry (str): The key for the current configuration setting being processed. This
                corresponds to a field (name) in both IniKey and CfgKey, which in turn
                are ini section entries keys and settings keys.
        ini_key (str): the key for the ini file entry, used for logging.
        file_path (Path): The path to the configuration file being processed, used for logging.
    """
    # get the valid choices for 'entry'
    allowed_options: FrozenSet[str] = getattr(CfgKey, entry + Part.joiner + Part.choice)
    if ini_value in allowed_options:
        settings[settings_key] = ini_value
    else:
        logging.error(
            'Invalid %s value "%s" found in "%s". Valid values are: %s',
            ini_key, ini_value, file_path, ', '.join(allowed_options))

def _update_set_from_string(ini_value: str, target: Set[str], entry: str, **kwargs) -> None:
    """
    Updates (configuration) set based on a string from a configuration file entry.

    Args:
        ini_value (str): The value read from a configuration file
        target (Set[str]): The settings entry to be updated
        entry (str): The key for the current configuration setting being processed. This
                corresponds to a field (name) in both IniKey and CfgKey, which in turn
                are ini section entries keys and settings keys.
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
        update_set_keywords(target, ini_value, good_set, negation_prefix=CfgKey.negation_prefix,
                            source_entry=getattr(IniKey, entry), **kwargs)

if __name__ == "__main__":
    app = CompareModuleAPI()

# pylint:disable=line-too-long
# cSpell:words configparser pathlib expanduser getboolean posix getint getfloat metavar issubset docstrings dunder
# cSpell:ignore nargs appdata
# cSpell:allowCompoundWords true
