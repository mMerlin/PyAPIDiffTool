# SPDX-FileCopyrightText: 2024 H Phil Duby
# SPDX-License-Identifier: MIT

"""
`profiling utilities`
==================

A collection of utility functions to support profiling of python object
API information

"""

from typing import Hashable, Callable

from generic_tools import SentinelTag, LoggerMixin, StrOrTag
from introspection_tools import (
    ObjectContextData, ParameterDetail,
    Tag as ITag, AttributeProfileKey as Key, ProfileConstant as PrfC, InspectIs as Is,
    AttributeProfile,
)
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

def validate_profile_data(name: str, implementation: ObjectContextData,  # pylint:disable=too-many-branches
                          profile: AttributeProfile) -> None:
    """
    Do some sanity checks on the prototype profile information structure.

    Args:
        name (str): The name of an attribute.
        implementation (ObjectContextData): context information for the attribute and profile.
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
    assert len(profile[Key.source]) == Key.source_elements, \
        f'{len(profile[Key.source]).__name__ = } ¦ {name}¦{profile}'
    assert isinstance(profile[Key.source][Key.file], (str, SentinelTag)), \
        f'{type(profile[Key.source][Key.file]).__name__ = }' + \
        f' ¦ {name}¦{profile}'
    if isinstance(profile[Key.source][Key.file], SentinelTag):
        assert profile[Key.source][Key.file] is SentinelTag(ITag.NO_SOURCE), \
            f'{type(profile[Key.source][Key.file]).__name__ = }' + \
            f' ¦ {name}¦{profile}'
        if profile[Key.source][Key.module] is not None:
            assert profile[Key.source][Key.module] is implementation.module, \
                f'{profile[Key.source][Key.file]} ' + \
                f'{type(profile[Key.source][Key.module]).__name__ = }' + \
                f' ¦ {name}¦{profile}'
    else:
        assert profile[Key.source][Key.module] is not None, \
            f'{profile[Key.source][Key.file]} ' + \
            f'{type(profile[Key.source][Key.module]).__name__ = }' + \
            f' ¦ {name}¦{profile}'
    assert isinstance(profile[Key.tags], tuple), \
        f'{type(profile[Key.tags]).__name__ = } ¦ {name}¦{profile}'
    # assert profile[Key.tags] contains 0 or more str
    assert isinstance(profile[Key.details], tuple), \
        f'{type(profile[Key.details]).__name__ = } ¦ {name}¦{profile}'
    assert len(profile[Key.details]) == Key.detail_elements, \
        f'{len(profile[Key.details]) = } ¦ {name}¦{profile}'
    assert isinstance(profile[Key.details][Key.context], StrOrTag), \
        f'{type(profile[Key.details][Key.context]).__name__ = }' + \
        f' ¦ {name}¦{profile[Key.details]}'
    if isinstance(profile[Key.details][Key.context], SentinelTag):
        LoggerMixin.get_logger().error('incomplete refactoring. Found '
            f'{profile[Key.details][Key.context]} being used as the context key for profile ' +
            f'details.\n{name}¦{profile[Key.details]}')
        raise ApplicationLogicError(
            f'incomplete refactoring: found {profile[Key.details][Key.context]} used for profile '
            'details context. Continue the refactoring')
    if not isinstance(profile[Key.details][Key.context], str):
        raise ApplicationLogicError(
            f'profile details context "{profile[Key.details][Key.context]}" should be a str: ' +
            f'found {type(profile[Key.details][Key.context])}.')
    if isinstance(profile[Key.details][Key.context], str):
        assert profile[Key.details][Key.context] in (Is.ROUTINE, Is.MODULE, Is.BUILTIN,
                Is.DATADESCRIPTOR, PrfC.A_CLASS, PrfC.namedtuple,
                PrfC.PKG_CLS_INST, PrfC.DUNDER, PrfC.DATA_LEAF, PrfC.DATA_NODE,
                PrfC.signature, PrfC.unhandled_value
            ), f'str but {profile[Key.details][Key.context] = } ¦ {name}¦{profile}'
        if profile[Key.details][Key.context] in (PrfC.A_CLASS, PrfC.PKG_CLS_INST):
            assert profile[Key.details][Key.detail] \
                is SentinelTag(PrfC.expandable), 'expected expand: ' \
                f'{type(profile[Key.details][Key.detail]).__name__}' + \
                f' ¦ {name}¦{profile}'
        elif profile[Key.details][Key.context] == PrfC.DATA_LEAF:
            assert isinstance(profile[Key.details][Key.detail], (type(None), str,
                    int, float)), \
                f'leaf but {type(profile[Key.details][Key.detail]).__name__ = }' + \
                f' ¦ {name}¦{profile}'
        elif profile[Key.details][Key.context] == PrfC.signature or \
                profile[Key.details][Key.context] == Is.ROUTINE:
            assert isinstance(profile[Key.details][Key.detail], tuple), \
                f'{profile[Key.details][Key.context]} but ' + \
                f'{type(profile[Key.details][Key.detail]).__name__ = }' + \
                f' ¦ {name}¦{profile}\nis not tuple'
            assert len(profile[Key.details][Key.detail]) == Key.sig_elements, \
                f'{profile[Key.details][Key.context]} but ' + \
                f'{len(profile[Key.details][Key.detail]) = }' + \
                f' ¦ {name}¦{profile}\nis not {Key.sig_elements}'
            assert isinstance(profile[Key.details][Key.detail][Key.sig_parameters], tuple), \
                f'{profile[Key.details][Key.context]} but ' + \
                f'{type(profile[Key.details][Key.detail][Key.sig_parameters]).__name__ = }' + \
                f' ¦ {name}¦{profile}\nis not tuple'
            assert all(isinstance(ele, ParameterDetail)
                       for ele in profile[Key.details][Key.detail][Key.sig_parameters]), \
                f'{profile[Key.details][Key.context]} but ' + \
                f'{profile[Key.details][Key.detail][Key.sig_parameters] = }' + \
                f' ¦ {name}¦{profile}\nis not all ParameterDetail'
        elif profile[Key.details][Key.context] == PrfC.namedtuple:
            assert isinstance(profile[Key.details][Key.detail], str), \
                f'namedtuple but {type(profile[Key.details][Key.detail]).__name__ = }' + \
                f' ¦ {name}¦{profile}\nis not str'
        elif profile[Key.details][Key.context] == Is.BUILTIN:
            assert profile[Key.details][Key.detail] is SentinelTag(ITag.BUILTIN_EXCLUDE), \
                f'builtin but {type(profile[Key.details][Key.detail]).__name__ = }' + \
                f' ¦ {name}¦{profile}\nis not SentinelTag({ITag.BUILTIN_EXCLUDE})'
        elif profile[Key.details][Key.context] == Is.MODULE:
            raise ValueError(('"%s" module detected, should filter?: %s', name, str(profile)))
        # something else: app error?
        else:
            assert profile[Key.details][Key.context] == PrfC.DATA_NODE, \
                f'{type(profile[Key.details][Key.context]).__name__ = } ¦' + \
                f'{implementation.path}.{name}¦{profile}'
            assert profile[Key.tags] == (), \
                f'{profile[Key.tags] = } ¦{implementation.path}¦{name}¦{profile}'
            if profile[Key.data_type] not in ('list', 'dict', 'mappingproxy'):
                print(f'****2 {implementation.path} {name = }, {profile} ****')

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
    if len(profile_data[Key.details]) != Key.detail_elements:
        target(
            f'**** {len(profile_data[Key.details]) =} ¦ {name}¦{profile_data} ****')
        return True
    return False

# cSpell:words DATADESCRIPTOR, DUNDER
# cSpell:ignore
# cSpell:allowCompoundWords true
