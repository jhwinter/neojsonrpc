#####
Usage
#####

Here are simple guidelines regarding how to use the NeoJsonRPC client.

Client initialization
=====================

The first step to interact with the NEO JSON-RPC interface is to initialize a ``neojsonrpc.Client``
instance. The following examples respectively show how to get clients for the TestNet, the MainNet
and an hypothetical local PrivNet:

.. code-block:: python

    >>> from neojsonrpc import Client
    >>> testnet_client = Client.for_testnet()
    >>> mainnet_client = Client.for_mainnet()
    >>> privnet_client = Client(host='localhost', port='30333')

It should be noted that you can configure you client to interact with a JSON-RPC server over TLS
using the ``tls`` keyword argument:

.. code-block:: python

    >>> from neojsonrpc import Client
    >>> client = Client(host='seed3.neo.org', port=20331, tls=True)

Interacting with the blockchain
===============================

You can easily call some of the `JSON-RPC methods <http://docs.neo.org/en-us/node/api.html>`_ once
your client is initialized. These methods allow you to get various blockchain data from NEO nodes.
Here are some examples:

.. code-block:: python

    >>> from neojsonrpc import Client
    >>> client = Client.for_testnet()
    >>>
    >>> # Retrieve the block count.
    >>> client.get_block_count()
    977981
    >>>
    >>> # Retrieve the information associated with a specific block index.
    >>> client.get_block(977981)
    {'confirmations': 3,
     'hash': '0x155d6f65eb79730fcb98c8da07d216a150eab432803692c9c9aa04fc895c830d',
      'index': 977981,
      'merkleroot': '0x0e6abef01f17d2ce984fd215266db005b67f0f324df6bcf2b42b1b692226941f',
      'nextblockhash': '0xd7127e3b204b3c5e2ac71914f1a0bec5107e83203571b4e551364df60496d205',
      'nextconsensus': 'AdyQbbn6ENjqWDa5JNYMwN3ikNcA4JeZdk',
      'nonce': '42bfbbe8b95c8796',
      'previousblockhash': '0x3f1438acc3c949fa9f97181cefb4b4f0e376d996c25398bc70159ae75e52be00',
      'script': {'invocation': '402432acc12f362031be5d4da6cbeda3a9b7aa61482e234b979f96e30d051278c4ad5711e86e136cf9a6a8450626a88ec82d300c653fe04441c565500d84e830cb40722819145260429c87be0804459857ad5d273af36f976e045ecd660afb76990395ceb183ae95427147c47b54c2c1d6678341c850dd320b70af36aaab81f22bb7401e65f039c288f77dbc5fdc68f990c1901e9b20cf66805ff6a9e4e4c7528cc4e7b8c50d7e166e292e72a11f51a5b851a2b92f1bfe6fe12c01914722116c20347e40f7fbfbe25e1465b1120dd7b7d8f1bb1d501f8d1433808b53926be7ef6a08010e729b3520d2e31ea0436d2034ebf3481dd82df98c2833e9614e3d5fa2efa3a12e40002815ea581330df0e1e01bdecbd96e133ed06949c112555f8b9b2f1c49387cd2df198fcec1a1e94c66a55a27c2852f39a398a05f65859acba74eb9d29dea467',
      'verification': '55210209e7fd41dfb5c2f8dc72eb30358ac100ea8c72da18847befe06eade68cebfcb9210327da12b5c40200e9f65569476bbff2218da4f32548ff43b6387ec1416a231ee821034ff5ceeac41acf22cd5ed2da17a6df4dd8358fcb2bfb1a43208ad0feaab2746b21026ce35b29147ad09e4afe4ec4a7319095f08198fa8babbe3c56e970b143528d2221038dddc06ce687677a53d54f096d2591ba2302068cf123c1f2d75c2dddc542557921039dafd8571a641058ccc832c5e2111ea39b09c0bde36050914384f7a48bce9bf92102d02b1873a0863cd042cc717da31cea0d7cf9db32b74d4c72c01b0011503e2e2257ae'},
      'size': 987,
      'time': 1515362895,
      'tx': [{'attributes': [],
              'net_fee': '0',
              'nonce': 3109848982,
              'scripts': [],
              'size': 10,
              'sys_fee': '0',
              'txid': '0xd0884f26dc433e40f45ac5a5c310979e8a9c14925ba8523582933e2905cf51ed',
              'type': 'MinerTransaction',
              'version': 0,
              'vin': [],
              'vout': []},
             {'attributes': [],
              'gas': '0',
              'net_fee': '0',
              'script': '4cf67b227265636f72644964223a227265636f72645f746573745f39383335222c226164647265737346726f6d223a2230303a44303a39363a37373a39323a4334222c22666f726d5032704964223a223834393337346636323239373431366361353234393462616630316236633933222c2261646472657373546f223a226363653263323465373739633461363339373834316165653561336239623661222c22746f5032704964223a226164376263326663643130613437306261626337333530643361663233653262222c22716c63223a2237363732222c2274696d65223a22323031382d30312d30382030363a30383a3030227d107265636f72645f746573745f3938333552c103707574676d6e117953310c0a6dc79d0fcff59916dbdb7c5e',
              'scripts': [],
              'size': 301,
              'sys_fee': '0',
              'txid': '0x5c9cdc113a7adb58320786f2be8009b1fb723bd164b6d9e6025f019203beeeb8',
              'type': 'InvocationTransaction',
              'version': 1,
              'vin': [],
              'vout': []}],
     'version': 0}

.. note::

    Please refer to :doc:`client_reference` for a full list of the available methods.

Invoking & testing smart contracts
==================================

NeoJsonRPC implements the ``invoke``, ``invokefunction`` and ``invokescript`` methods provided by
NEO nodes through the JSON-RPC interface. It should be noted that these methods are to test VM
scripts as if they wre ran on the blockchain. The underlying RPC calls don't affect the blockchain
in any way (no transaction is generated, nothing is stored on the contract's storage). Here is a
simple example using the ``invoke_function`` method:

.. code-block:: python

    >>> from neojsonrpc import Client
    >>> client = Client.for_testnet()
    >>> result = client.invoke_function('34af1b6634fcd7cfcff0158965b18601d3837e32', 'symbol', [])
    {'gas_consumed': '0.217',
     'stack': [{'type': 'ByteArray', 'value': bytearray(b'TKN')}],
     'state': 'HALT, BREAK'}

    >>> client.invoke_function('9aff1e08aea2048a26a3d2ddbb3df495b932b1e7', True, 'balanceOf', [{
    'type': 5, 'value': '056320a11ec9b0e1c6645f5b25cf7b2fc354fd49'}])
    {'state': 'HALT, BREAK',
    'gas_consumed': '0.345',
    'stack': [{'type': 'ByteArray', 'value': bytearray(b'\x00P\xdb\xbb\xa6!')}]}

It should be noted that NeoJsonRPC provides a more high-level interface for interacting with
contract fonctions as if they were Python class instance methods:

.. code-block:: python

    >>> contract = client.contract('34af1b6634fcd7cfcff0158965b18601d3837e32')
    >>> contract.symbol()
    {'gas_consumed': '0.217',
     'stack': [{'type': 'ByteArray', 'value': bytearray(b'TKN')}],
     'state': 'HALT, BREAK'}

    >>> client.contract('9aff1e08aea2048a26a3d2ddbb3df495b932b1e7').balanceOf(True,
    {'type': 5, 'value': '056320a11ec9b0e1c6645f5b25cf7b2fc354fd49'})
    {'state': 'HALT, BREAK',
    'gas_consumed': '0.345',
    'stack': [{'type': 'ByteArray', 'value': bytearray(b'\x00P\xdb\xbb\xa6!')}]}
