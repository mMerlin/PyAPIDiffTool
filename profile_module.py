# SPDX-FileCopyrightText: 2024 H Phil Duby
# SPDX-License-Identifier: MIT

"""manage profiling information for a single module"""

from dataclasses import dataclass
import logging
import types
from typing import Callable, Iterable, Union, Tuple, Any, FrozenSet
from app_error_framework import ApplicationLogicError
from config_package import ProfileConfiguration, Setting
from generic_tools import (
    SentinelTag, LoggerMixin,
    import_module,
)
from introspection_tools import (
    ObjectContextData,
    AttributeProfileKey as APKey,
    ProfileConstant as PrfC,
    Tag as ITag,
    attribute_name_compare_key,
    get_attribute_info,
    populate_object_context,
)

@dataclass(frozen=True)
class Idx:
    """
    Named constants for lookup indices and keys
    """
    info_name: int = 0
    info_profile: int = 1

    all_scope: str = 'all'
    public_scope: str = 'public'
    published_scope: str = 'published'

@dataclass(frozen=True)
class Tag:
    """Constants for SentinelTag instances, to avoid possible typos in strings used to
    create or compare them.
    """
    excluded_name: str = 'Exclude by name'
    dont_yield: str = 'Do Not Yield'
    """attribute name is to be skipped"""

class ProfileModule:
    """Manage introspection and api profiling for a single module"""
    def __init__(self, module_path: str, configuration: ProfileConfiguration,
                skip_reporter: Callable[[str, Any], None]):
        """
        Initialize the ProfileModule.

        Args:
            module_path (str): Path to the module to be profiled.
            configuration (ProfileConfiguration): Configuration settings for profiling.
            skip_reporter (Callable[[str, Any], None]): A callable that handles skipped attribute
                reporting. It should accept a message format string and additional arguments
                to format the string.  A logging method (IE logging.info()) will work.
        """
        self._cfg = configuration
        self.context_data = ObjectContextData(path=module_path, element=import_module(module_path))
        self._attr_names = frozenset()
        self._ignorable_attributes = frozenset()
        self._report_skipped = skip_reporter

    def update_context(self, path: Tuple[str], element: object) -> None:
        """
        change the context information for a specific path and element, to handle recursing into
        the module information.

        Args:
            path (Tuple): path to object, normally starting at the root module
            element (object): the element to continue profiling from)
        """
        self.context_data = ObjectContextData(path=path, element=element)

    def profile_attributes(self, use_all_scope: bool) -> Iterable[Tuple[str, Tuple]]:
        """
        Yields attribute profile information in custom sorted order, handling errors and filtering.

        Args:
            use_all_scope (bool): Override the configured scope to use 'all' if True.

        Yields:
            Iterable[Tuple[str, Tuple]]: Attributes and their profile data after processing.
        """
        self._initialize_iteration_context()
        attr_names = self._get_attribute_names_for_context(use_all_scope)
        for name in sorted(attr_names, key=attribute_name_compare_key):
            attribute_profile = self._profile_attribute(name)
            if attribute_profile is not SentinelTag(Tag.dont_yield):
                yield attribute_profile

    def _initialize_iteration_context(self) -> None:
        """
        Initializes the context for iterating object attributes by setting up scope-based
        attribute names and a set of ignorable attribute names.
        """
        populate_object_context(self.context_data)
        # Set up attribute names that are to be skipped for the current context
        ignore = set(self._cfg.get(Setting.IGNORE_GLOBAL_ATTRIBUTES.name))
        if self.context_data.mode == PrfC.MODULE_MODE:
            ignore.update(self._cfg.get(Setting.IGNORE_MODULE_ATTRIBUTES.name))
        if self.context_data.mode == PrfC.CLASS_MODE:
            ignore.update(self._cfg.get(Setting.IGNORE_CLASS_ATTRIBUTES.name))
        self._ignorable_attributes = frozenset(ignore)

    def _get_attribute_names_for_context(self, use_all_scope: bool) -> FrozenSet[str]:
        """
        Get the attribute names for the current scope and context

        Args:
            use_all_scope (bool): Whether to override scope settings to use all attributes.

        Returns
            (FrozenSet) names of attributes available for the current context and scope.
        """
        attr_scope = Idx.all_scope if use_all_scope else self._cfg.get(Setting.SCOPE.name)
        if self.context_data.mode in (PrfC.SEQUENCE_MODE, PrfC.KEY_VALUE_MODE):
            # For sequence and dict type elements only look at the contained elements
            attr_scope = Idx.published_scope
        return {
            Idx.all_scope: self.context_data.all,
            Idx.published_scope: self.context_data.published \
                if self.context_data.published else self.context_data.public,
            Idx.public_scope: self.context_data.public
        }.get(attr_scope, self.context_data.all)

    def _profile_attribute(self, name: str) -> Union[
            Tuple[Tuple[int, str], Tuple], SentinelTag]:
        """
        Get profile information for a single attribute and determine if it should be yielded.

        Args:
            name (str): The name of the attribute to profile.

        Returns:
            Either a tuple with attribute data for yielding or SentinelTag(Tag.dont_yield)
            if the attribute should be skipped (not yielded).
        """
        if name in self._ignorable_attributes:
            # Skip ignored attribute names
            self._report_iterate_skip((attribute_name_compare_key(name),
                                       SentinelTag(Tag.excluded_name)))
            return SentinelTag(Tag.dont_yield)

        raw_profile = get_attribute_info(self.context_data, name)
        if raw_profile[Idx.info_name] != name:
            raise ApplicationLogicError('get_attribute_info should return the requested attribute '
                                        f'name: "{raw_profile[Idx.info_name]}" not equal "{name}"')
        attr_profile = (attribute_name_compare_key(name),) + raw_profile[1:]

        if raw_profile[Idx.info_profile] is SentinelTag(ITag.ERROR_ACCESS_FAILURE):
            self._report_skipped('**** Error accessing {} "{}" attribute: {}',
                                 self.context_data.path, name, attr_profile)
            self.context_data.skipped += 1
            return SentinelTag(Tag.dont_yield)

        if self._filter_by_source(name, attr_profile):
            return SentinelTag(Tag.dont_yield)

        key = attr_profile[Idx.info_profile][APKey.details][APKey.context]
        if key in [SentinelTag(ITag.SYS_EXCLUDE), SentinelTag(ITag.BUILTIN_EXCLUDE)]:
            self._report_iterate_skip(attr_profile)
            return SentinelTag(Tag.dont_yield)

        return attr_profile

    def _filter_by_source(self, name: str, result: tuple) -> bool:
        """
        detect attribute (profiles) that are to be skipped based on the source (module)

        Args:
            name (str): the name of the attribute being profiled
            result (tuple): collected profile information for the attribute

        Returns True if the attribute is to be discarded, else False
        """
        src_file, src_module = result[Idx.info_profile][APKey.source]
        if not ((src_file is SentinelTag(ITag.NO_SOURCE) and src_module is None) or \
                ((src_file == self.context_data.source or src_file is SentinelTag(ITag.NO_SOURCE)) \
                 and src_module is self.context_data.module)):
            if src_file is SentinelTag(ITag.BUILTIN_EXCLUDE):
                self._report_iterate_skip(result)
                return True
            if not isinstance(src_module, types.ModuleType):
                raise ApplicationLogicError('source module should be a ModuleType: Found '
                    f'{type(src_module).__name__} for {name} in {self.context_data.path}: {result}')
            if not(src_file is SentinelTag(ITag.NO_SOURCE) or
                    src_file is SentinelTag(ITag.GET_SOURCE_FAILURE) or
                    isinstance(src_file, str)):
                raise ApplicationLogicError(
                    'source file should be a string or specific SentinelTag: Found '
                    f'{type(src_file).__name__} for {name} in {self.context_data.path}: {result}')
            self._report_iterate_skip(result)
            return True
        return False

    def _report_iterate_skip(self, result: tuple) -> None:
        """
        report an attribute being skipped before it is yielded

        Args:
            result (tuple): the information collected for the attribute implementation
                # (SentinelTag): marker when no attempt has been made to collect attribute
                # information
        """
        assert isinstance(result, tuple), \
            f'skip result expected to be tuple: Found {type(result)} {result}' # DEBUG
        self._report_skipped(f'{self.context_data.path} {result}')
        self.context_data.skipped += 1


# Usage example:
def main():
    """wrapper so pylint does not think variables should be constants"""
    test_app = "test"
    test_logger = LoggerMixin.get_logger() # "profile_module"
    test_logger.addHandler(logging.StreamHandler())
    settings = ProfileConfiguration(test_app, test_logger.name)
    profile = ProfileModule('logging', settings, test_logger)
    attr_profile = profile.profile_attributes(False)
    print(next(attr_profile))

if __name__ == '__main__':
    main()


# cSpell:words
# cSpell:ignore dont
# cSpell:allowCompoundWords true
