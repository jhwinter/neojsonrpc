from neojsonrpc import Client


class TestClient:
    def test_can_return_the_state_of_an_account(self):
        client = Client.for_testnet()
        account = client.get_account_state('ALn85kUVLWWZdCuZfvjwbmusWH9Hx43XuF')
        assert 'balances' in account
        assert account['balances']

    def test_can_return_the_state_of_an_asset(self):
        client = Client.for_testnet()
        asset = client.get_asset_state(
            'c56f33fc6ecfcd0c225c4ab356fee59390af8560be0e930faebe74a6daff7c9b')  # NEO
        assert asset['amount'] == '100000000'
        assert asset['available'] == '100000000'
        assert asset['precision'] == 0

    def test_can_return_the_best_block_hash(self):
        client = Client.for_testnet()
        best_block_hash = client.get_best_block_hash()
        assert len(best_block_hash[2:]) == 64

    def test_can_return_block_information_associated_with_a_block_hash(self):
        client = Client.for_testnet()
        block = client.get_block('9e38052ac0827e490b917bd69174cfa0fae9a7f77db18ed3cf2ee95922e0103d')
        assert block['hash'] == '0x9e38052ac0827e490b917bd69174cfa0fae9a7f77db18ed3cf2ee95922e0103d'
        assert block['index']

    def test_can_return_the_block_count(self):
        client = Client.for_testnet()
        assert client.get_block_count() > 0

    def test_can_return_the_block_hash_associated_with_an_index(self):
        client = Client.for_testnet()
        block_hash = client.get_block_hash(970238)
        assert block_hash == '0x631be7a0fc5bc684bd756003576d5b9ecccb096a636d5e86e951513d3bba537c'

    def test_can_return_system_fees_associated_with_a_block_hash(self):
        client = Client.for_testnet()
        fees = client.get_block_sys_fee(966045)
        assert fees == '716234'

    def test_can_return_the_connection_count(self):
        client = Client.for_testnet()
        connection_count = client.get_connection_count()
        assert connection_count

    def test_can_return_the_state_of_a_contract(self):
        client = Client.for_testnet()
        contract = client.get_contract_state('f9572c5b119a6b5775a6af07f1cef5d310038f55')
        assert contract['hash'] == '0xf9572c5b119a6b5775a6af07f1cef5d310038f55'

    def test_can_return_a_list_of_unconfirmed_transactions_associated_with_the_node(self):
        client = Client.for_testnet()
        mempool = client.get_raw_mem_pool()
        assert isinstance(mempool, list)

    def test_can_return_detailed_information_associated_with_a_transaction_hash(self):
        client = Client.for_testnet()
        tx = client.get_raw_transaction(
            'b96bd2b0070a4b25f47b390225da100b96ddcbe28c9af1f34cbb34462bf3db22')
        assert tx['txid'] == '0xb96bd2b0070a4b25f47b390225da100b96ddcbe28c9af1f34cbb34462bf3db22'
        assert tx['size'] == 145
        assert tx['blocktime'] == 1515210609

    def test_can_return_a_value_stored_in_the_storage_of_a_specific_contract(self):
        client = Client.for_testnet()
        val = client.get_storage('34af1b6634fcd7cfcff0158965b18601d3837e32', 'totalSupply')
        assert isinstance(val, bytearray)
        val = int.from_bytes(val, 'little')
        assert val == 100000000000
        assert not client.get_storage('34af1b6634fcd7cfcff0158965b18601d3837e32', 'dummyKey')

    def test_can_return_the_transaction_output_information_associated_with_a_hash_and_index(self):
        client = Client.for_testnet()
        txout = client.get_tx_out(
            '6ed78234b2d4ac886f4f6246a19d237be38d6541e59d87b547987778314bb7af', 0)
        assert txout is None

    def test_can_return_node_peers(self):
        client = Client.for_testnet()
        peers = client.get_peers()
        assert peers

    def test_can_invoke_a_contract(self):
        client = Client.for_testnet()
        result = client.invoke('34af1b6634fcd7cfcff0158965b18601d3837e32', ['symbol', []])
        assert result['state'] == 'HALT, BREAK'
        assert result['stack'] == [{'type': 'ByteArray', 'value': bytearray(b'FOX')}]

    def test_can_invoke_a_contract_with_a_specific_function(self):
        client = Client.for_testnet()
        result = client.invoke_function('34af1b6634fcd7cfcff0158965b18601d3837e32', 'symbol', [])
        assert result['state'] == 'HALT, BREAK'
        assert result['stack'] == [{'type': 'ByteArray', 'value': bytearray(b'FOX')}]

    def test_can_invoke_a_contract_using_a_script(self):
        client = Client.for_testnet()
        result = client.invoke_script('000673796d626f6c67327e83d30186b1658915f0cfcfd7fc34661baf34')
        assert result['state'] == 'HALT, BREAK'
        assert result['stack'] == [{'type': 'ByteArray', 'value': bytearray(b'FOX')}]

    def test_can_send_a_raw_transaction(self):
        client = Client.for_testnet()
        result = client.send_raw_transaction(
            '80000001195876cb34364dc38b730077156c6bc3a7fc570044a66fbfeeea56f71327e8ab0000029b7cffda'
            'a674beae0f930ebe6085af9093e5fe56b34a5c220ccdcf6efc336fc500c65eaf440000000f9a23e06f74cf'
            '86b8827a9108ec2e0f89ad956c9b7cffdaa674beae0f930ebe6085af9093e5fe56b34a5c220ccdcf6efc33'
            '6fc50092e14b5e00000030aab52ad93f6ce17ca07fa88fc191828c58cb71014140915467ecd359684b2dc3'
            '58024ca750609591aa731a0b309c7fb3cab5cd0836ad3992aa0a24da431f43b68883ea5651d548feb6bd3c'
            '8e16376e6e426f91f84c58232103322f35c7819267e721335948d385fae5be66e7ba8c748ac15467dcca06'
            '93692dac')
        assert result is False

    def test_can_validate_an_address(self):
        client = Client.for_testnet()
        assert client.validate_address('ASkaarMYjqdbcBpvLTFNXJhyonXR8K9Xx3')['isvalid']
        assert not client.validate_address('A=BSkaarMYjqdbcBpvLTFNXJhyonXR8K9Xx3')['isvalid']

    def test_can_invoke_a_contract_function_as_a_method(self):
        client = Client.for_testnet()
        result = client.contract('34af1b6634fcd7cfcff0158965b18601d3837e32').symbol()
        assert result['state'] == 'HALT, BREAK'
        assert result['stack'] == [{'type': 'ByteArray', 'value': bytearray(b'FOX')}]
