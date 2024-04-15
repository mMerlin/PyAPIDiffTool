# SPDX-FileCopyrightText: 2024 H Phil Duby
# SPDX-License-Identifier: MIT

"""manage profiling information for a single module"""

import types
import logging
from typing import Iterable, Union, Tuple, FrozenSet
from introspection_tools import (
    ObjectContextData,
    AttributeProfileKey as APKey,
    ProfileConstant as PrfC,
    Tag as ITag,
    attribute_name_compare_key,
    get_attribute_info,
    populate_object_context,
)
from generic_tools import (
    SentinelTag, LoggerMixin,
    import_module,
)
from config_package import ProfileConfiguration, Setting
from app_error_framework import ApplicationLogicError

class Idx:
    """
    Named constants for lookup indices and keys
    """
    info_name: int = 0
    info_profile: int = 1

    all_scope: str = 'all'
    public_scope: str = 'public'
    published_scope: str = 'published'

class Tag:
    """Constants for SentinelTag instances, to avoid possible typos in strings used to
    create or compare them.
    """
    excluded_name: str = 'Exclude by name'
    dont_yield: str = 'Do Not Yield'
    """attribute name is to be skipped"""

class ProfileModule:
    """Manage introspection and api profiling for a single module"""
    def __init__(self, module_path: str, configuration: ProfileConfiguration):
        # self.module_path = module_path
        self._cfg = configuration
        self.context_data = ObjectContextData(path=module_path, element=import_module(module_path))
        self.profile_data = {}
        self._attr_names: FrozenSet = None
        self._ignorable_attributes: FrozenSet = frozenset(set())
        # self._reports[PrToKey.REPORT_ATTRIBUTE_SKIPPED]
        self._skipped_logger = LoggerMixin.get_logger()  # Temporary

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
            self._skipped_logger.error(('**** Error accessing {} "{}" attribute: {}',
                                        self.context_data.path, name, attr_profile))
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
        self._skipped_logger.info(('{} {}', self.context_data.path, result))
        self.context_data.skipped += 1

    def get_profile(self):
        """
        Return the collected profile data
        """
        return self.profile_data

# Usage example:
def main():
    """wrapper so pylint does not think variables should be constants"""
    test_app = "test"
    test_logger = LoggerMixin.get_logger() # "profile_module"
    test_logger.addHandler(logging.StreamHandler())
    settings = ProfileConfiguration(test_app, test_logger.name)
    profile = ProfileModule('logging', settings)
    attr_profile = profile.profile_attributes(False)
    print(next(attr_profile))

if __name__ == '__main__':
    main()


# cSpell:words
# cSpell:ignore dont
# cSpell:allowCompoundWords true

# # Usage in compare_module_api
# base_module_profile = ProfileModule(base_module_path)
# port_module_profile = ProfileModule(port_module_path)

# base_module_profile.populate_context()
# port_module_profile.populate_context()

# base_module_profile.profile_attribute()
# port_module_profile.profile_attribute()

# # Now compare the profile_data of both modules
# compare_profiles(base_module_profile.get_profile(), port_module_profile.get_profile())
