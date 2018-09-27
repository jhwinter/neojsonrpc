"""
    NEO JSON-RPC client constants
    =============================

    This module defines top-level constants that can be used all tools or classes provided by
    neojsonrpc, such as the JSON-RPC client.

"""

from enum import Enum


class JSONRPCMethods(Enum):
    """ Defines the values of the NEO JSON-RPC methods. """

    # The 'getaccountstate' method allows to check account asset information according to an account
    # address.
    GET_ACCOUNT_STATE = 'getaccountstate'

    # The 'getassetstate' method allows to query the asset information, based on a specified asset
    # number.
    GET_ASSET_STATE = 'getassetstate'

    # The 'getbestblockhash' method allows to get the hash of the tallest block in the main chain.
    GET_BEST_BLOCK_HASH = 'getbestblockhash'

    # The 'getblock' method allows to fetch the block information associated with a specific hash
    # value or block index (block height).
    GET_BLOCK = 'getblock'

    # The 'getblockcount' method allows to get the number of blocks in the chain.
    GET_BLOCK_COUNT = 'getblockcount'

    # The 'getblockhash' method allows to get the hash associated with a specific block index.
    GET_BLOCK_HASH = 'getblockhash'

    # The 'getblocksysfee' method allows to get the system fees of a block identified by a specific
    # block index.
    GET_BLOCK_SYS_FEE = 'getblocksysfee'

    # The 'getconnectioncount' method allows to get the current number of connections for the
    # considered node.
    GET_CONNECTION_COUNT = 'getconnectioncount'

    # The 'getcontractstate' method allows to query contract information associated with a specific
    # script hash.
    GET_CONTRACT_STATE = 'getcontractstate'

    # The 'getrawmempool' method allows to get a list of unconfirmed transactions in memory.
    GET_RAW_MEM_POOL = 'getrawmempool'

    # The 'getrawtransaction' method allows to get detailed information associated with a specific
    # transaction hash.
    GET_RAW_TRANSACTION = 'getrawtransaction'

    # The 'getstorage' method allows to get a value stored in the storage associated with a specific
    # contract script hash and a specific key.
    GET_STORAGE = 'getstorage'

    # The 'gettxout' method allows to get the transaction output information corresponding to a
    # specified hash and index.
    GET_TX_OUT = 'gettxout'

    # The 'getpeers' method allows to get a list of nodes that the considered node is currently
    # connected/disconnected from.
    GET_PEERS = 'getpeers'

    # The 'getversion' method allows to get version information about the considered node.
    GET_VERSION = 'getversion'

    # The 'invoke' method allows to invoke a contract (associated with a specific script hash) with
    # potential parameters and to return the result. It should be noted that calling this method
    # does not affect the blockchain in any way: the targeted contract is executed with the given
    # parameters but the contract's storage remain unchanged.
    INVOKE = 'invoke'

    # The 'invokefunction' method allows to invoke a contract (associated with a specific script
    # hash) by specifying an operation and potential parameters. It should be noted that calling
    # this method does not affect the blockchain in any way: the targeted contract is executed with
    # the given parameters but the contract's storage remain unchanged.
    INVOKE_FUNCTION = 'invokefunction'

    # The 'invokescript' method allows to invoke a specific script that'll be run through the VM and
    # to get the corresponding result. This method is to test VM script as if they were ran on the
    # blockchain at a specific point in time. This RPC call does not affect the blockchain in any
    # way.
    INVOKE_SCRIPT = 'invokescript'

    # The 'sendrawtransaction' method allows to broadcast a transaction over the NEO network.
    SEND_RAW_TRANSACTION = 'sendrawtransaction'

    # The 'validateaddress' method allows to validate if a string is a valid NEO address.
    VALIDATE_ADDRESS = 'validateaddress'


class ContractParameterTypes(Enum):
    """ Defines the contract parameter types supported by the NEO JSON-RPC endpoints. """

    BOOLEAN = 'Boolean'
    INTEGER = 'Integer'
    HASH160 = 'Hash160'
    HASH256 = 'Hash256'
    BYTE_ARRAY = 'ByteArray'
    STRING = 'String'
    ARRAY = 'Array'
