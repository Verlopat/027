"""Real local-Anvil adapter for signed PABLA-v2 EVM checkpoints.

All transactions return genuine chain receipts. This adapter never silently
falls back to a memory ledger, and does not assume public-chain finality.
"""
from __future__ import annotations
import json
from pathlib import Path
from .checkpoint import Checkpoint,Sealed
from .schedule import PublicSchedule

class EvmV2Ledger:
    backend='anvil-evm'
    def __init__(self,rpc:str='http://127.0.0.1:8545',artifact='contracts/out/AnchorLogV2.sol/AnchorLogV2.json',address=None,account=None):
        try:from web3 import Web3
        except ImportError as e:raise RuntimeError('Install chain extra: uv sync --extra chain') from e
        a=json.loads(Path(artifact).read_text())
        self.web3=Web3(Web3.HTTPProvider(rpc,request_kwargs={'timeout':20}))
        if not self.web3.is_connected():raise ConnectionError('No local EVM node connected; no fallback')
        self.account=account or self.web3.eth.accounts[0]
        self.abi=a['abi']
        self.bytecode=a['bytecode']['object']
        if address:
            self.contract=self.web3.eth.contract(address=self.web3.to_checksum_address(address),abi=self.abi)
        else:self.contract=None
    def _tx(self,fn):
        from web3.exceptions import ContractLogicError,ContractCustomError,TransactionNotFound
        try:
            tx=fn.transact({'from':self.account})
            receipt=self.web3.eth.wait_for_transaction_receipt(tx,timeout=60)
        except (ContractLogicError,ContractCustomError,ValueError) as e:
            raise ValueError(f'EVM transaction rejected: {e}') from e
        if receipt.status!=1:raise ValueError(f'failed EVM transaction: {receipt.transactionHash.hex()}')
        return {'backend':self.backend,'tx_hash':receipt.transactionHash.hex(),
                'block':receipt.blockNumber,'gas_used':receipt.gasUsed,
                'chain_id':int(self.web3.eth.chain_id)}
    def deploy(self):
        if self.contract is not None:raise ValueError('already deployed')
        factory=self.web3.eth.contract(abi=self.abi,bytecode=self.bytecode)
        data=self._tx(factory.constructor())
        receipt=self.web3.eth.get_transaction_receipt(data['tx_hash'])
        self.contract=self.web3.eth.contract(address=receipt.contractAddress,abi=self.abi)
        return {**data,'contract_address':receipt.contractAddress}
    def register(self,collector:bytes,epoch:int,schedule:PublicSchedule):
        if self.contract is None:raise ValueError('contract not deployed')
        return self._tx(self.contract.functions.register(collector,epoch,schedule.first,schedule.height,schedule.root))
    @staticmethod
    def cp_tuple(cp:Checkpoint):
        return (cp.domain,cp.collector,cp.epoch,cp.period,cp.size,cp.root,
                cp.prev,cp.wall_ms,cp.schedule_root)
    def anchor(self,sealed:Sealed):
        if self.contract is None:raise ValueError('contract not deployed')
        return self._tx(self.contract.functions.anchor(self.cp_tuple(sealed.checkpoint),sealed.signature,list(sealed.key_proof)))
    def prove_equivocation(self,a:Sealed,b:Sealed):
        if self.contract is None:raise ValueError('contract not deployed')
        return self._tx(self.contract.functions.proveEquivocation(self.cp_tuple(a.checkpoint),a.signature,
                      self.cp_tuple(b.checkpoint),b.signature,list(a.key_proof)))
    def latest(self,collector:bytes,epoch:int):
        if self.contract is None:raise ValueError('contract not deployed')
        period,size,digest,root=self.contract.functions.heads(collector,epoch).call()
        return {'period':period,'size':size,'digest':digest.hex(),'root':root.hex()}
    def revoked_at(self,collector:bytes,epoch:int)->int:
        if self.contract is None:raise ValueError('contract not deployed')
        return int(self.contract.functions.revokedAt(collector,epoch).call())
