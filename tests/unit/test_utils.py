from neojsonrpc.utils import (decode_invocation_result, encode_invocation_params, is_hash160,
                              is_hash256)


def test_is_hash256_helper_works():
    assert is_hash256('936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af')
    assert not is_hash256('dummy')
    assert not is_hash256('98c615784ccb5fe5936fbc0cbe9dfdb408d92f0f')


def test_is_hash160_helper_works():
    assert is_hash160('98c615784ccb5fe5936fbc0cbe9dfdb408d92f0f')
    assert not is_hash160('dummy')
    assert not is_hash160('936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af')
    assert not is_hash160('98c615784ccb5fe5936fbc0Ébe9dfdb408d92f0f')


class TestEncodeInvocationParamsHelper:
    def test_can_encode_a_boolean(self):
        assert encode_invocation_params([True, False, ]) == \
            [{'type': 'Boolean', 'value': True}, {'type': 'Boolean', 'value': False}, ]

    def test_can_encode_an_integer(self):
        assert encode_invocation_params([42, ]) == [{'type': 'Integer', 'value': 42}, ]

    def test_can_encode_a_hash256(self):
        assert encode_invocation_params(
            ['936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af', ]) == \
            [{'type': 'Hash256',
              'value': '936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af'}, ]

    def test_can_encode_a_hash160(self):
        assert encode_invocation_params(
            ['98c615784ccb5fe5936fbc0cbe9dfdb408d92f0f', ]) == \
            [{'type': 'Hash160', 'value': '98c615784ccb5fe5936fbc0cbe9dfdb408d92f0f'}, ]

    def test_can_encode_a_byte_array(self):
        assert encode_invocation_params([bytearray('test'.encode('utf-8')), ]) == \
            [{'type': 'ByteArray', 'value': bytearray('test'.encode('utf-8'))}, ]

    def test_can_encode_a_string(self):
        assert encode_invocation_params(['Hello', ]) == [{'type': 'String', 'value': 'Hello'}, ]

    def test_can_encode_an_array(self):
        assert encode_invocation_params([[1, 3, 6], ]) == \
            [{'type': 'Array',
              'value': [{'type': 'Integer', 'value': 1}, {'type': 'Integer', 'value': 3},
                        {'type': 'Integer', 'value': 6}]}]


class TestDecodeInvocationResultHelper:
    def test_do_nothing_if_stack_results_are_not_present(self):
        result = {
            'gas_consumed': '0.334',
            'script': '00000',
            'state': 'HALT, BREAK',
            'tx': '00000',
        }
        assert decode_invocation_result(result) == result

    def test_can_decode_byte_array_values(self):
        result = {
            'gas_consumed': '0.334',
            'script': '00000',
            'stack': [{'type': 'ByteArray', 'value': '68747470733a2f2f6e656f2e6f7267'}],
            'state': 'HALT, BREAK',
            'tx': '00000',
        }
        assert decode_invocation_result(result) == \
            {
                'gas_consumed': '0.334',
                'script': '00000',
                'stack': [{'type': 'ByteArray', 'value': bytearray(b'https://neo.org')}],
                'state': 'HALT, BREAK',
                'tx': '00000', }

    def test_can_decode_array_values(self):
        result = {
            'gas_consumed': '0.334',
            'script': '00000',
            'stack': [{'type': 'Array',
                       'value': [{'type': 'ByteArray',
                                  'value': '68747470733a2f2f6e656f2e6f7267'}]}],
            'state': 'HALT, BREAK',
            'tx': '00000',
        }
        assert decode_invocation_result(result) == \
            {
                'gas_consumed': '0.334',
                'script': '00000',
                'stack': [{'type': 'Array',
                           'value': [{'type': 'ByteArray',
                                      'value': bytearray(b'https://neo.org')}]}],
                'state': 'HALT, BREAK',
                'tx': '00000', }

    def test_can_decode_integer_values(self):
        result = {
            'gas_consumed': '0.334',
            'script': '00000',
            'stack': [{'type': 'Integer', 'value': '4'}],
            'state': 'HALT, BREAK',
            'tx': '00000',
        }
        assert decode_invocation_result(result) == \
            {
                'gas_consumed': '0.334',
                'script': '00000',
                'stack': [{'type': 'Integer', 'value': 4}],
                'state': 'HALT, BREAK',
                'tx': '00000', }
