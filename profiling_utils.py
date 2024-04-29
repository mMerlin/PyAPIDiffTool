# SPDX-FileCopyrightText: 2024 H Phil Duby
# SPDX-License-Identifier: MIT

"""
`profiling utilities`
==================

A collection of utility functions to support profiling of python object
API information

"""

from typing import Hashable, Callable, cast

from generic_tools import SentinelTag, LoggerMixin, StrOrTag
from introspection_tools import (
    ParameterDetail,
    Tag as ITag, AttributeProfileKey as Key, ProfileConstant as PrfC, InspectIs as Is,
    AttributeProfile, LeafDataType
)
from profile_module import ProfileModule
from app_error_framework import ApplicationLogicError

def annotation_str(annotation: StrOrTag, sentinel: SentinelTag) -> str:
    """
    Format an annotation string or tag for display.

    This uses a custom (recognizably not standard ascii) value when an expected
    SentinelTag is provided in place of an annotation string. This is taken as
    a marker that no annotation exists, as separate from an annotation that
    exists, but is empty or None.

    Args:
        annotation (StrOrTag): annotation detail information.
        sentinel (SentinelTag): The context specific tag indicating no annotation exists

    Returns (str) Formatted annotation information, without the SentinelTag
    """
    return '«none»' if annotation is sentinel else f'"{annotation:s}"'

def default_str(default: Hashable) -> str:
    """
    Format a profile default value or tag for display.

    Args:
        default (Hashable): The collected default value profile

    Returns (str) Formatted default value information, without the SentinelTag. This
        includes the typehint for the default value, when it exists.
    """
    return '«none»' if default is SentinelTag(ITag.NO_DEFAULT) \
        else '"None"' if default is None else \
        f':{type(default).__name__} "{default}"'

def validate_profile_data(name: str, implementation: ProfileModule,  # pylint:disable=too-many-branches
                          profile: AttributeProfile) -> None:
    """
    Do some sanity checks on the prototype profile information structure.

    Args:
        name (str): The name of an attribute.
        implementation (ProfileModule): context information for the attribute and profile.
        profile (AttributeProfile): The profile information for the implemented attribute.
    """
    assert isinstance(name, str), \
        f'{type(name).__name__ = } ¦ {name}¦{profile}'
    # AttributeProfile
    assert isinstance(profile, tuple), \
        f'{type(profile).__name__ = } ¦ {name}¦{profile}'
    assert len(profile) == Key.root_elements, \
        f'{len(profile) = } ¦ {name}¦{profile}'
    assert isinstance(profile[Key.annotation], StrOrTag), \
        f'{type(profile[Key.annotation]).__name__ = } ¦ {name}¦{profile}'
    assert isinstance(profile[Key.data_type], str), \
        f'{type(profile[Key.data_type]).__name__ = } ¦ {name}¦{profile}'
    assert isinstance(profile[Key.source], tuple), \
        f'{type(profile[Key.source]).__name__ = } ¦ {name}¦{profile}'
    prof_key_src = cast(tuple, profile[Key.source])
    assert len(prof_key_src) == Key.source_elements, \
        f'{len(prof_key_src) = } ¦ {name}¦{profile}'
    assert isinstance(prof_key_src[Key.file], StrOrTag), \
        f'{type(prof_key_src[Key.file]).__name__ = }' + \
        f' ¦ {name}¦{profile}'
    if isinstance(prof_key_src[Key.file], SentinelTag):
        assert prof_key_src[Key.file] is SentinelTag(ITag.NO_SOURCE), \
            f'{type(prof_key_src[Key.file]).__name__ = }' + \
            f' ¦ {name}¦{profile}'
        if prof_key_src[Key.module] is not None:
            assert prof_key_src[Key.module] is implementation.context_data.module, \
                f'{prof_key_src[Key.file]} ' + \
                f'{type(prof_key_src[Key.module]).__name__ = }' + \
                f' ¦ {name}¦{profile}'
    else:
        assert prof_key_src[Key.module] is not None, \
            f'{prof_key_src[Key.file]} ' + \
            f'{type(prof_key_src[Key.module]).__name__ = }' + \
            f' ¦ {name}¦{profile}'
    assert isinstance(profile[Key.tags], tuple), \
        f'{type(profile[Key.tags]).__name__ = } ¦ {name}¦{profile}'
    prof_key_tags = cast(tuple, profile[Key.tags])
    assert all(isinstance(tag, str) for tag in prof_key_tags), \
        f'Tags {prof_key_tags = } not all strings ¦ {name}¦{profile}'
    assert isinstance(profile[Key.details], tuple), \
        f'{type(profile[Key.details]).__name__ = } ¦ {name}¦{profile}'
    prof_key_details = cast(tuple, profile[Key.details])
    assert len(prof_key_details) == Key.detail_elements, \
        f'{len(prof_key_details) = } ¦ {name}¦{profile}'
    assert isinstance(prof_key_details[Key.context], StrOrTag), \
        f'{type(prof_key_details[Key.context]).__name__ = }' + \
        f' ¦ {name}¦{prof_key_details}'
    if isinstance(prof_key_details[Key.context], SentinelTag):
        LoggerMixin.get_logger().error('incomplete refactoring. Found '
            f'{prof_key_details[Key.context]} being used as the context key for profile ' +
            f'details.\n{name}¦{prof_key_details}')
        raise ApplicationLogicError(
            f'incomplete refactoring: found {prof_key_details[Key.context]} used for profile '
            'details context. Continue the refactoring')
    if not isinstance(prof_key_details[Key.context], str):
        raise ApplicationLogicError(
            f'profile details context "{prof_key_details[Key.context]}" should be a str: ' +
            f'found {type(prof_key_details[Key.context])}.')
    # isinstance(prof_key_details[Key.context], str)
    assert prof_key_details[Key.context] in (Is.ROUTINE, Is.MODULE, Is.BUILTIN,
            Is.DATADESCRIPTOR, PrfC.A_CLASS, PrfC.namedtuple,
            PrfC.PKG_CLS_INST, PrfC.DUNDER, PrfC.DATA_LEAF, PrfC.DATA_NODE,
            PrfC.signature, PrfC.unhandled_value
        ), f'str but {prof_key_details[Key.context] = } ¦ {name}¦{profile}'
    if prof_key_details[Key.context] in (Is.DATADESCRIPTOR, PrfC.A_CLASS, PrfC.PKG_CLS_INST):
        assert prof_key_details[Key.detail] \
            is SentinelTag(PrfC.expandable), 'expected expand: ' \
            f'{type(prof_key_details[Key.detail]).__name__}' + \
            f' ¦ {name}¦{profile}'
    elif prof_key_details[Key.context] == PrfC.DATA_LEAF:
        assert isinstance(prof_key_details[Key.detail], LeafDataType), \
            f'leaf but {type(prof_key_details[Key.detail]).__name__ = }' + \
            f' ¦ {name}¦{profile}'
    elif prof_key_details[Key.context] == PrfC.signature or \
            prof_key_details[Key.context] == Is.ROUTINE:
        assert isinstance(prof_key_details[Key.detail], tuple), \
            f'{prof_key_details[Key.context]} but ' + \
            f'{type(prof_key_details[Key.detail]).__name__ = }' + \
            f' ¦ {name}¦{profile}\nis not tuple'
        assert len(prof_key_details[Key.detail]) == Key.sig_elements, \
            f'{prof_key_details[Key.context]} but ' + \
            f'{len(prof_key_details[Key.detail]) = }' + \
            f' ¦ {name}¦{profile}\nis not {Key.sig_elements}'
        assert isinstance(prof_key_details[Key.detail][Key.sig_parameters], tuple), \
            f'{prof_key_details[Key.context]} but ' + \
            f'{type(prof_key_details[Key.detail][Key.sig_parameters]).__name__ = }' + \
            f' ¦ {name}¦{profile}\nis not tuple'
        assert all(isinstance(ele, ParameterDetail)
                    for ele in prof_key_details[Key.detail][Key.sig_parameters]), \
            f'{prof_key_details[Key.context]} but ' + \
            f'{prof_key_details[Key.detail][Key.sig_parameters] = }' + \
            f' ¦ {name}¦{profile}\nis not all ParameterDetail'
    elif prof_key_details[Key.context] == PrfC.namedtuple:
        assert isinstance(prof_key_details[Key.detail], str), \
            f'namedtuple but {type(prof_key_details[Key.detail]).__name__ = }' + \
            f' ¦ {name}¦{profile}\nis not str'
    elif prof_key_details[Key.context] == Is.BUILTIN:
        assert prof_key_details[Key.detail] is SentinelTag(ITag.BUILTIN_EXCLUDE), \
            f'builtin but {type(prof_key_details[Key.detail]).__name__ = }' + \
            f' ¦ {name}¦{profile}\nis not SentinelTag({ITag.BUILTIN_EXCLUDE})'
    elif prof_key_details[Key.context] == Is.MODULE:
        raise ValueError(('"%s" module detected, should filter?: %s', name, str(profile)))
    # something else: app error?
    else:
        assert prof_key_details[Key.context] == PrfC.DATA_NODE, \
            f'{type(prof_key_details[Key.context]).__name__ = } ¦' + \
            f'{implementation.context_data.path}.{name}¦{profile}'
        assert prof_key_tags == (), \
            f'{prof_key_tags = } ¦{implementation.context_data.path}¦{name}¦{profile}'
        if profile[Key.data_type] not in ('list', 'dict', 'mappingproxy'):
            print(f'****2 {implementation.context_data.path} {name = }, {profile} ****')

def report_profile_data_exceptions(target: Callable, name: str,
                                   profile_data: AttributeProfile) -> bool:
    """
    Report some exception cases that are not severe enough to abort further processing.

    Args:
        destination (Logger): the report (segment) to append any exception information to
        name (str): The name of an attribute.
        profile_data (Tuple): The profile information for base or port implementation attribute.
            Tuple[StrOrTag, str, Tuple[str], Tuple[tuple, StrOrTag]]

    Returns:
        True when an exception case has been detected and reported
        False when no exception case has been detected
    """
    details_count = len(profile_data)
    if details_count != Key.root_elements:
        target(f'**** {details_count =} ¦ {name}¦{profile_data} ****')
        return True
    if not isinstance(profile_data[Key.details], tuple):
        target(
            f'**** {type(profile_data[Key.details]).__name__ =} ¦ {name}¦{profile_data} '
            '****')
        return True
    if len(cast(tuple, profile_data[Key.details])) != Key.detail_elements:
        target(
            f'**** {len(cast(tuple, profile_data[Key.details])) =} ¦ {name}¦{profile_data} ****')
        return True
    return False

# cSpell:words DATADESCRIPTOR, DUNDER
# cSpell:ignore
# cSpell:allowCompoundWords true
