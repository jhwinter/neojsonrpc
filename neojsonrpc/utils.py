"""
    NEO JSON-RPC client utilities
    =============================

    This module defines utilities and shortcuts used by the NEO JSON-RPC client.

"""

import binascii
import copy
import re

from .constants import ContractParameterTypes


def is_hash256(s):
    """ Returns True if the considered string is a valid SHA256 hash.

    :param str s: the considered string
    :return: Returns True if the considered string is a valid SHA256 hash.
    :rtype: bool
    """
    if not s or not isinstance(s, str):
        return False
    return re.match('^[0-9A-F]{64}$', s.strip(), re.IGNORECASE)


def is_hash160(s):
    """ Returns True if the considered string is a valid RIPEMD160 hash.

    :param str s: the considered string
    :return: Returns True if the considered string is a valid RIPEMD160 hash.
    :rtype: bool
    """
    if not s or not isinstance(s, str):
        return False
    if not len(s) == 40:
        return False
    for c in s:
        if (c < '0' or c > '9') and (c < 'A' or c > 'F') and (c < 'a' or c > 'f'):
            return False
    return True


def encode_invocation_params(has_type=False, params=None):
    """ Returns a list of parameters meant to be passed to JSON-RPC endpoints.

    :param bool has_type: whether or not the user has defined the 'type' of the 'value' they're
    passing
    :param list params: list of parameters
    :return: Returns a list of parameters meant to be passed to JSON-RPC endpoints.
    """
    final_params = []
    if has_type and isinstance(params, dict):
        final_params.append(params)
    for p in params:
        if has_type and isinstance(p, dict):
            final_params.append(p)
        else:
            if isinstance(p, bool):
                final_params.append({'type': ContractParameterTypes.BOOLEAN.value, 'value': p})
            elif isinstance(p, int):
                final_params.append({'type': ContractParameterTypes.INTEGER.value, 'value': p})
            elif is_hash160(p):
                final_params.append({'type': ContractParameterTypes.HASH160.value, 'value': p})
            elif is_hash256(p):
                final_params.append({'type': ContractParameterTypes.HASH256.value, 'value': p})
            elif isinstance(p, bytearray):
                final_params.append({'type': ContractParameterTypes.BYTE_ARRAY.value, 'value': p})
            elif isinstance(p, str):
                final_params.append({'type': ContractParameterTypes.STRING.value, 'value': p})
            elif isinstance(p, list):
                if p and isinstance(p[0], dict) and 'type' in p[0]:
                    innerp = encode_invocation_params(has_type=True, params=p)
                else:
                    innerp = encode_invocation_params(params=p)
                final_params.append({'type': ContractParameterTypes.ARRAY.value, 'value': innerp})
    return final_params


def decode_invocation_result(result):
    """ Tries to decode the values embedded in an invocation result dictionary.

    :param dict result: the results returned by the JSON-RPC query
    :return: the decoded values embedded in the invocation result dictionary
    :rtype: dict
    """
    if 'stack' not in result:
        return result
    result = copy.deepcopy(result)
    result['stack'] = _decode_invocation_result_stack(stack=result['stack'])
    return result


def _decode_invocation_result_stack(stack):
    """ Decodes the values in the stack

    :param list stack:
    :return: list of stack results
    :rtype: list
    """
    stack = copy.deepcopy(stack)
    for value_dict in stack:
        if value_dict['type'] == 'Array':
            value_dict['value'] = _decode_invocation_result_stack(stack=value_dict['value'])
        elif value_dict['type'] == 'ByteArray':
            value_dict['value'] = bytearray(binascii.unhexlify(value_dict['value'].encode('utf-8')))
    return stack
