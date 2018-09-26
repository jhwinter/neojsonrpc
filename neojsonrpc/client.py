"""
    NEO JSON-RPC client
    ===================

    This module defines the ``Client`` class allowing to interact with the JSON-RPC endpoints.

"""

import binascii
import json

import requests
from requests.adapters import HTTPAdapter
from requests.exceptions import HTTPError

from .constants import JSONRPCMethods
from .exceptions import ProtocolError, TransportError
from .utils import decode_invocation_result, encode_invocation_params


class Client:
    """ The NEO JSON-RPC client class. """

    def __init__(self, host=None, port=None, tls=False, http_max_retries=None):
        """ Initializes the Client used to connect to the blockchain

        :param str host: host to connect to
        :param int port: port to access
        :param bool tls: whether or not to us Transport Layer Security Protocol
        :param int http_max_retries: maximum amount of times the client will try to connect to a peer before it quits
        """
        # Initializes attributes related to the client settings (host, port, etc).
        self.host = host or 'localhost'
        self.port = port or 30333
        self.tls = tls
        self.session = requests.Session()
        self.session.mount(self.host, HTTPAdapter(max_retries=http_max_retries or 3))

        # Initializes an "ID counter" that'll be used to forge each request to the JSON-RPC
        # endpoint. The "id" parameter is "required" in order to help clients sort responses out.
        # In the case of the current client, we'll just ensure that this value gets incremented
        # after each request made to the JSON-RPC endpoint.
        self._id_counter = 0

    # TODO: I want to make the hosts/ports more dynamic for for_mainnet() and for_testnet()
    # I will probably try to use this project https://github.com/jhwinter/neo-python-protocol-maker to help keep the
    # hosts/ports constantly updated. The client wasn't working when I first downloaded this project due to the
    # hosts being down
    @classmethod
    def for_mainnet(cls):
        """ Creates a ``Client`` instance for use with the NEO Main Net. """
        return cls(host='seed1.ngd.network', port=10332)

    @classmethod
    def for_testnet(cls):
        """ Creates a ``Client`` instance for use with the NEO Test Net. """
        return cls(host='seed3.neo.org', port=20332)

    def contract(self, script_hash):
        """ Returns a ``ContractWrapper`` instance allowing to easily invoke contract functions.

        This method allows to invoke smart contract functions as if they were Python class instance
        methods. For example:

        .. code-block:: python

            >>> client = Client.for_testnet()
            >>> contract = client.contract('34af1b6634fcd7cfcff0158965b18601d3837e32')
            >>> contract.symbol()
            {...}
            >>> contract.getBalance('<address>')
            {...}

        :param str script_hash: contract script hash
        :return: :class:`ContractWrapper <ContractWrapper>` object
        :rtype: neojsonrpc.client.ContractWrapper

        """
        return ContractWrapper(self, script_hash)

    ####################
    # JSON-RPC METHODS #
    ####################

    def get_account_state(self, address, **kwargs):
        """ Returns the account state information associated with a specific address.

        :param str address: a 34-bit length address (eg. AJBENSwajTzQtwyJFkiJSv7MAaaMc7DsRz)
        :return: dictionary containing the account state information
        :rtype: dict

        """
        return self._call(JSONRPCMethods.GET_ACCOUNT_STATE.value, params=[address, ], **kwargs)

    def get_asset_state(self, asset_id, **kwargs):
        """ Returns the asset information associated with a specific asset ID.

        :param str asset_id:
            an asset identifier (the transaction ID of the RegistTransaction when the asset is
            registered)
        :return: dictionary containing the asset state information
        :rtype: dict

        """
        return self._call(JSONRPCMethods.GET_ASSET_STATE.value, params=[asset_id, ], **kwargs)

    def get_best_block_hash(self, **kwargs):
        """ Returns the hash of the tallest block in the main chain.

        :return: hash of the tallest block in the chain
        :rtype: str

        """
        return self._call(JSONRPCMethods.GET_BEST_BLOCK_HASH.value, **kwargs)

    def get_block(self, block_hash, verbose=True, **kwargs):
        """ Returns the block information associated with a specific hash value or block index.

        :param str or int block_hash: a block hash value or a block index (block height)
        :param bool verbose:
            a boolean indicating whether the detailed block information should be returned in JSON
            format (otherwise the block information is returned as an hexadecimal string by the
            JSON-RPC endpoint)
        :return:
            dictionary containing the block information (or an hexadecimal string if verbose is set
            to False)
        :rtype: dict or str

        """
        return self._call(JSONRPCMethods.GET_BLOCK.value, params=[block_hash, int(verbose), ], **kwargs)

    def get_block_count(self, **kwargs):
        """ Returns the number of blocks in the chain.

        :return: number of blocks in the chain
        :rtype: int

        """
        return self._call(JSONRPCMethods.GET_BLOCK_COUNT.value, **kwargs)

    def get_block_hash(self, block_index, **kwargs):
        """ Returns the hash value associated with a specific block index.

        :param int block_index: a block index (block height)
        :return: hash of the block associated with the considered index
        :rtype: str

        """
        return self._call(JSONRPCMethods.GET_BLOCK_HASH.value, [block_index, ], **kwargs)

    def get_block_sys_fee(self, block_index, **kwargs):
        """ Returns the system fees associated with a specific block index.

        :param int block_index: a block index (block height)
        :return: system fees of the block, expressed in NeoGas units
        :rtype: str

        """
        return self._call(JSONRPCMethods.GET_BLOCK_SYS_FEE.value, [block_index, ], **kwargs)

    def get_connection_count(self, **kwargs):
        """ Returns the current number of connections for the considered node.

        :return: number of connections for the node
        :rtype: int

        """
        return self._call(JSONRPCMethods.GET_CONNECTION_COUNT.value, **kwargs)

    def get_contract_state(self, script_hash, **kwargs):
        """ Returns the contract information associated with a specific script hash.

        :param str script_hash: contract script hash
        :return: dictionary containing the contract information
        :rtype: dict

        """
        return self._call(JSONRPCMethods.GET_CONTRACT_STATE.value, [script_hash, ], **kwargs)

    def get_raw_mem_pool(self, **kwargs):
        """ Returns a list of unconfirmed transactions in memory associated with the node.

        :return: list of unconfirmed transaction hashes
        :rtype: list

        """
        return self._call(JSONRPCMethods.GET_RAW_MEM_POOL.value, **kwargs)

    def get_raw_transaction(self, tx_hash, verbose=True, **kwargs):
        """ Returns detailed information associated with a specific transaction hash.

        :param str tx_hash: transaction hash
        :param bool verbose:
            a boolean indicating whether the detailed transaction information should be returned in
            JSON format (otherwise the transaction information is returned as an hexadecimal string
            by the JSON-RPC endpoint)
        :return:
            dictionary containing the transaction information (or an hexadecimal string if verbose
            is set to False)
        :rtype: dict or str

        """
        return self._call(JSONRPCMethods.GET_RAW_TRANSACTION.value, params=[tx_hash, int(verbose), ], **kwargs)

    def get_storage(self, script_hash, key, **kwargs):
        """ Returns the value stored in the storage of a contract script hash for a given key.

        :param str script_hash: contract script hash
        :param str key: key to look up in the storage
        :return: value associated with the storage key
        :rtype: bytearray

        """
        hexkey = binascii.hexlify(key.encode('utf-8')).decode('utf-8')
        hexresult = self._call(JSONRPCMethods.GET_STORAGE.value, params=[script_hash, hexkey, ], **kwargs)
        try:
            assert hexresult
            result = bytearray(binascii.unhexlify(hexresult.encode('utf-8')))
        except AssertionError:
            result = hexresult
        return result

    def get_tx_out(self, tx_hash, index, **kwargs):
        """ Returns the transaction output information corresponding to a hash and index.

        :param str tx_hash: transaction hash
        :param int index: index of the transaction output to be obtained in the transaction (starts from 0)
        :return: dictionary containing the transaction output
        :rtype: dict

        """
        return self._call(JSONRPCMethods.GET_TX_OUT.value, params=[tx_hash, index, ], **kwargs)

    def get_peers(self, **kwargs):
        """ Returns a list of nodes that the node is currently connected/disconnected from.

        :return: dictionary containing the nodes the current node is connected/disconnected from
        :rtype: dict

        """
        return self._call(JSONRPCMethods.GET_PEERS.value, **kwargs)

    def get_version(self, **kwargs):
        """ Returns version information about the current node.

        :return: dictionary containing version information about the current node
        :rtype: dict

        """
        return self._call(JSONRPCMethods.GET_VERSION.value, **kwargs)

    def invoke(self, script_hash, has_type, params, **kwargs):
        """ Invokes a contract with given parameters and returns the result.

        It should be noted that the name of the function invoked in the contract should be part of
        paramaters.

        :param str script_hash: contract script hash
        :param bool has_type: whether or not the type is included with the params
        :param list params: list of paramaters to be passed in to the smart contract
        :return: result of the invocation
        :rtype: dictionary

        """
        contract_params = encode_invocation_params(has_type=has_type, params=params)
        raw_result = self._call(JSONRPCMethods.INVOKE.value, [script_hash, contract_params, ], **kwargs)
        return decode_invocation_result(result=raw_result)

    def invoke_function(self, script_hash, operation, has_type, params, **kwargs):
        """ Invokes a contract's function with given parameters and returns the result.

        :param str script_hash: contract script hash
        :param str operation: name of the operation to invoke
        :param bool has_type: whether or not the type is included with the params
        :param list params: list of parematers to be passed in to the smart contract
        :return: result of the invocation
        :rtype: dictionary

        """
        contract_params = encode_invocation_params(has_type=has_type, params=params)
        raw_result = self._call(JSONRPCMethods.INVOKE_FUNCTION.value, [script_hash, operation, contract_params, ],
                                **kwargs)
        return decode_invocation_result(result=raw_result)

    def invoke_script(self, script, **kwargs):
        """ Invokes a script on the VM and returns the result.

        :param str script: script runnable by the VM
        :return: result of the invocation
        :rtype: dictionary

        """
        raw_result = self._call(JSONRPCMethods.INVOKE_SCRIPT.value, [script, ], **kwargs)
        return decode_invocation_result(raw_result)

    def send_raw_transaction(self, hextx, **kwargs):
        """ Broadcasts a transaction over the NEO network and returns the result.

        :param str hextx: hexadecimal string that has been serialized
        :return: result of the transaction
        :rtype: bool

        """
        return self._call(JSONRPCMethods.SEND_RAW_TRANSACTION.value, [hextx, ], **kwargs)

    def validate_address(self, addr, **kwargs):
        """ Validates if the considered string is a valid NEO address.

        :param str addr: string containing a potential NEO address
        :return: dictionary containing the result of the verification
        :rtype: dictionary

        """
        return self._call(JSONRPCMethods.VALIDATE_ADDRESS.value, [addr, ], **kwargs)

    ##################################
    # PRIVATE METHODS AND PROPERTIES #
    ##################################

    def _call(self, method, params=None, request_id=None):
        """ Calls the JSON-RPC endpoint.

        :param str method: method to be called
        :param list params: parameters to be passed
        :param int request_id: id required to help sort clients out
        :return: results of the invocation
        :rtype: dict
        """
        params = params or []

        # Determines which 'id' value to use and increment the counter associated with the current
        # client instance if applicable.
        rid = request_id or self._id_counter
        if request_id is None:
            self._id_counter += 1

        # Prepares the payload and the headers that will be used to forge the request.
        payload = {'jsonrpc': '2.0', 'method': method, 'params': params, 'id': rid}
        headers = {'Content-Type': 'application/json'}
        scheme = 'https' if self.tls else 'http'
        url = f'{scheme}://{self.host}:{self.port}'
        response = ''  # setting this to an empty string to remove a warning message

        # Calls the JSON-RPC endpoint!
        try:
            response = self.session.post(url=url, headers=headers, data=json.dumps(payload))
            response.raise_for_status()
        except HTTPError:
            raise TransportError(f'Got unsuccessful response from server (status code: {response.status_code}',
                                 response=response)

        # Ensures the response body can be deserialized to JSON.
        try:
            response_data = response.json()
        except ValueError as e:
            raise ProtocolError(f'Unable to deserialize response body: {e}', response=response)

        # Properly handles potential errors.
        if response_data.get('error'):
            code = response_data['error'].get('code', '')
            message = response_data['error'].get('message', '')
            raise ProtocolError(f'Error[{code}] {message}', response=response, data=response_data)
        elif 'result' not in response_data:
            raise ProtocolError('Response is empty (result field is missing)', response=response, data=response_data)

        return response_data['result']


class ContractWrapper:
    """ Strategy class allowing to provide a high-level interface for invoking smart contracts. """

    def __init__(self, client, script_hash):
        """ Initialize the ContractWrapper

        :param Client client: Client object
        :param str script_hash: contract's script hash
        """
        self.client = client
        self.script_hash = script_hash

    def __getattribute__(self, attr):
        """

        :param attr:
        :return:
        """
        try:
            return super(ContractWrapper, self).__getattribute__(attr)
        except AttributeError:
            client = super(ContractWrapper, self).__getattribute__('client')
            script_hash = super(ContractWrapper, self).__getattribute__('script_hash')
            return ContractFunctionWrapper(client=client, script_hash=script_hash, funcname=attr)


class ContractFunctionWrapper:
    """ Strategy class allowing to easily invoke smart contract functions. """

    def __init__(self, client, script_hash, funcname):
        """ Initialize the ContractFunctionWrapper

        :param Client client: client used to connect to the JSON-RPC endpoints
        :param str script_hash: script hash of the contract
        :param str funcname: contract operation to be performed
        """
        self.client = client
        self.script_hash = script_hash
        self.funcname = funcname

    def __call__(self, has_type=False, *args):
        """ This is executed when someone tries to execute a contract's operation

        :param bool has_type:
            whether or not the user is passing in the 'type' along with the 'value'.
            if True, args must all be dict types
        :param args:
        :return: results of the function invocation
        """
        has_type = has_type or False
        return self.client.invoke_function(self.script_hash, self.funcname, has_type, args)
