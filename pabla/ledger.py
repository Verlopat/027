"""Ledger adapters. InMemoryLedger is expressly NOT a blockchain.

The Anvil adapter invokes a Solidity contract with state-enforcing methods and verifies
transaction receipts; Python never treats an RPC submission as final without status 1.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any
from .protocol import ProtocolError, Batch, is_hex32, digest


def collector_key(name: str) -> str:
    if not isinstance(name, str) or not name:
        raise ProtocolError("invalid collector name")
    return digest("PABLA-COLLECTOR-ID-v1", name)


class InMemoryLedger:
    """Explicit deterministic test double; measurements MUST be labelled non-chain."""
    backend = "in-memory-test-only"
    def __init__(self, clock: float | None = None) -> None:
        self._identities: dict[tuple[str, int], dict[str, Any]] = {}
        self._anchors: dict[tuple[str, int, int], dict[str, Any]] = {}
        self._fi_schedules: dict[tuple[str,int],list[dict]] = {}
        self.block = 1
        self.clock = clock if clock is not None else time.time()
        self.calls = 0
    def register(self, collector: str, epoch: int, public_key: str, *, recovery: str = "00" * 32, policy_name: str = "P1") -> dict:
        from .protocol import Policy
        Policy.for_name(policy_name)
        if not is_hex32(public_key) or not is_hex32(recovery) or epoch < 1:
            raise ProtocolError("invalid key, recovery, or epoch")
        if (collector, epoch) in self._identities:
            raise ProtocolError("epoch already registered")
        if epoch > 1:
            prev = self.identity(collector, epoch - 1)
            if not prev or not prev["revoked_block"]:
                raise ProtocolError("previous epoch must be revoked")
        self.block += 1
        self.calls += 1
        self._identities[collector, epoch] = {"public_key": public_key, "revoked_block": 0, "recovery": recovery, "policy": policy_name}
        return {"block_number": self.block, "block_timestamp": self.clock}
    def register_fi(self, collector: str, epoch: int, root: str, count: int,
                    *, policy_name: str = "FI", witness_public_key: str | None = None) -> dict:
        if policy_name not in ("FI", "FI-noerase", "FI-nochain") or not 1 <= count <= 10000:
            raise ProtocolError("invalid FI registration")
        result=self.register(collector,epoch,root,policy_name=policy_name)
        self._identities[(collector,epoch)]["forward_integrity"]=True
        if witness_public_key is not None:
            if not is_hex32(witness_public_key):
                raise ProtocolError("invalid independent witness public key")
            self._identities[(collector,epoch)]["witness_public_key"]=witness_public_key
        self._fi_schedules[(collector,epoch)]=[{"root":root,"start":1,"count":count}]
        return result

    def renew_fi(self, collector: str, epoch: int, root: str, count: int) -> dict:
        rec=self.identity(collector,epoch)
        if not rec or not rec.get("forward_integrity") or rec["revoked_block"] or not is_hex32(root) or not 1 <= count <= 10000:
            raise ProtocolError("invalid FI schedule renewal")
        self.block+=1
        self.calls+=1
        start=self.latest_period(collector,epoch)+1
        self._fi_schedules[(collector,epoch)].append({"root":root,"start":start,"count":count})
        return {"block_number":self.block,"block_timestamp":self.clock}

    def fi_schedule(self, collector: str, epoch: int, period: int) -> dict | None:
        for x in reversed(self._fi_schedules.get((collector,epoch), [])):
            if x["start"]<=period<x["start"]+x["count"]:
                return x
        return None

    def latest_period(self, collector: str, epoch: int) -> int:
        records=[r.get("period",0) for (c,e,_),r in self._anchors.items() if (c,e)==(collector,epoch)]
        return max(records,default=0)

    def revoke(self, collector: str, epoch: int) -> dict:
        rec = self.identity(collector, epoch)
        if not rec or rec["revoked_block"]:
            raise ProtocolError("unknown/already revoked epoch")
        self.block += 1
        self.calls += 1
        rec["revoked_block"] = self.block
        return {"block_number": self.block, "block_timestamp": self.clock}
    def identity(self, collector: str, epoch: int) -> dict | None:
        return self._identities.get((collector, epoch))
    def anchor(self, batch: Batch) -> dict:
        return self._record_anchor(batch, witness_signature=None)

    def anchor_attested(self, batch: Batch, *, witness_signature: str) -> dict:
        return self._record_anchor(batch, witness_signature=witness_signature)

    def _record_anchor(self, batch: Batch, *, witness_signature: str | None) -> dict:
        m = batch.manifest
        k = (m["collector_id"], m["epoch"], m["batch_number"])
        identity = self.identity(*k[:2])
        if not identity or identity["revoked_block"]:
            raise ProtocolError("unauthorized/revoked epoch")
        if m.get("method") != identity["policy"]:
            raise ProtocolError("registered policy mismatch")
        witness = identity.get("witness_public_key")
        if witness:
            from .protocol import valid_signature
            if not witness_signature or not valid_signature(witness,batch.manifest_digest,witness_signature):
                raise ProtocolError("independent witness authorization missing or invalid")
        if k in self._anchors:
            raise ProtocolError("duplicate anchor")
        if identity.get("forward_integrity"):
            p=m.get("period")
            schedule=self.fi_schedule(*k[:2],p) if type(p) is int else None
            if p != self.latest_period(*k[:2])+1 or p != k[2] or not schedule or m.get("schedule_root") != schedule["root"]:
                raise ProtocolError("FI period backfill or schedule mismatch")
        prev_key = (k[0], k[1], k[2] - 1)
        if k[2] == 1:
            if m["first_sequence"] != 1:
                raise ProtocolError("first epoch batch must start at 1")
        else:
            prev = self._anchors.get(prev_key)
            if not prev or prev["last_sequence"] + 1 != m["first_sequence"]:
                raise ProtocolError("nonconsecutive chain anchor")
            if identity["policy"] in ("P1", "A1", "A4", "A5", "FI", "FI-noerase", "FI-nochain") and m["previous_manifest_hash"] != prev["manifest_hash"]:
                raise ProtocolError("previous manifest commitment mismatch")
        self.block += 1
        self.calls += 1
        self.clock = max(self.clock, time.time())
        rec = {"manifest_hash": batch.manifest_digest, "merkle_root": m["merkle_root"],
               "last_chain": m["last_chain"], "first_sequence": m["first_sequence"],
               "last_sequence": m["last_sequence"], "block_number": self.block,
               "block_timestamp": self.clock,
               "tx_hash": digest("PABLA-TEST-RECEIPT", k[0], k[1], k[2], batch.manifest_digest)}
        if identity.get("forward_integrity"):
            rec["period"]=m["period"]
            rec["schedule_root"]=m["schedule_root"]
        self._anchors[k] = rec
        return rec
    def anchor_record(self, collector: str, epoch: int, batch_number: int) -> dict | None:
        return self._anchors.get((collector, epoch, batch_number))
    def latest(self, collector: str, epoch: int) -> tuple[int, int]:
        records = [b for (c,e,_),b in self._anchors.items() if c == collector and e == epoch]
        return (len(records), records[-1]["last_sequence"]) if records else (0, 0)


class AnvilLedger:
    """Real EVM RPC adapter for the CollectorAnchorRegistry contract.

    Contract bytecode must be compiled with pinned Foundry toolchain before use.
    The configured sender must be locally unlocked by Anvil; production keys and
    public networks are explicitly unsupported in this experiment adapter.
    """
    backend = "anvil-evm"
    def __init__(self, rpc: str, contract_address: str, abi_path: str, *, sender: str | None = None,
                 timeout_seconds: int = 60) -> None:
        try:
            from web3 import Web3
        except ImportError as exc:
            raise RuntimeError("Install the 'chain' dependency group: uv sync --extra chain") from exc
        if not (rpc.startswith("http://127.0.0.1:") or rpc.startswith("http://localhost:")):
            raise ProtocolError("experimental RPC must point to localhost Anvil")
        self.web3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": timeout_seconds}))
        if not self.web3.is_connected():
            raise ConnectionError(f"Anvil not reachable at {rpc}")
        if self.web3.eth.chain_id != 31337:
            raise ProtocolError("expected Anvil chain ID 31337")
        artifact = json.loads(Path(abi_path).read_text(encoding="utf-8"))
        abi = artifact["abi"] if isinstance(artifact, dict) else artifact
        self.contract = self.web3.eth.contract(address=Web3.to_checksum_address(contract_address), abi=abi)
        self.sender = sender or self.web3.eth.accounts[0]
        self.timeout_seconds = timeout_seconds
        self.calls = 0
    @staticmethod
    def b32(value: str) -> bytes:
        if not is_hex32(value):
            raise ProtocolError("contract bytes32 must be lowercase SHA256 hex")
        return bytes.fromhex(value)
    def _send(self, fn: Any) -> dict:
        try:
            from web3.exceptions import ContractCustomError, ContractLogicError, TimeExhausted
            txid = fn.transact({"from": self.sender})
            receipt = self.web3.eth.wait_for_transaction_receipt(txid, timeout=self.timeout_seconds)
        except (ContractCustomError, ContractLogicError, TimeExhausted, ValueError) as exc:
            # Preserve revert selector/data for reproducible failure classification.
            payload = getattr(exc, "data", None)
            raise ProtocolError(f"EVM transaction rejected: {type(exc).__name__}: {payload or str(exc)}") from exc
        if receipt["status"] != 1:
            raise ProtocolError("reverted anchor/registry transaction")
        self.calls += 1
        b = self.web3.eth.get_block(receipt["blockNumber"])
        tx_input = self.web3.eth.get_transaction(txid)["input"]
        payload_size = len(tx_input) if isinstance(tx_input, bytes) else len(bytes.fromhex(tx_input.removeprefix("0x")))
        return {"block_number": int(receipt["blockNumber"]), "block_timestamp": float(b["timestamp"]),
                "tx_hash": txid.hex(), "gas_used": int(receipt["gasUsed"]),
                "transaction_input_bytes": payload_size}
    def register(self, collector: str, epoch: int, public_key: str, *, recovery: str = "00" * 32, policy_name: str = "P1") -> dict:
        return self._send(self.contract.functions.register(self.b32(collector_key(collector)), epoch,
                                                      self.b32(public_key), self.sender, self.b32(recovery), self.b32(digest("PABLA-POLICY-v1", policy_name))))
    def register_fi(self, collector: str, epoch: int, root: str, count: int,
                    *, policy_name: str = "FI", witness_public_key: str | None = None) -> dict:
        if policy_name not in ("FI", "FI-noerase", "FI-nochain"):
            raise ProtocolError("invalid FI policy")
        key=self.b32(collector_key(collector))
        pol=self.b32(digest("PABLA-POLICY-v1",policy_name))
        if witness_public_key is None:
            return self._send(self.contract.functions.registerFI(key,epoch,
                                    self.b32(root),count,self.sender,pol))
        if not is_hex32(witness_public_key):
            raise ProtocolError("invalid witness public key")
        if len(self.web3.eth.accounts)<2:
            raise ProtocolError("Anvil needs a separately controlled witness account")
        witness_sender=next((x for x in self.web3.eth.accounts if x.lower()!=self.sender.lower()),None)
        if witness_sender is None:
            raise ProtocolError("witness sender must differ from collector")
        result=self._send(self.contract.functions.registerFIWitness(key,epoch,
                                self.b32(root),count,self.sender,witness_sender,pol))
        if not hasattr(self,'_witness_settings'):
            self._witness_settings={}
        self._witness_settings[(collector,epoch)]=(witness_public_key,witness_sender)
        return result

    def renew_fi(self, collector: str, epoch: int, root: str, count: int) -> dict:
        return self._send(self.contract.functions.renewFI(self.b32(collector_key(collector)),epoch,self.b32(root),count))

    def fi_schedule(self, collector: str, epoch: int, period: int) -> dict | None:
        root,start,count=self.contract.functions.getFISchedule(self.b32(collector_key(collector)),epoch,period).call()
        if not count:
            return None
        return {"root":bytes(root).hex(),"start":int(start),"count":int(count)}

    def latest_period(self, collector: str, epoch: int) -> int:
        return int(self.contract.functions.latestPeriod(self.b32(collector_key(collector)),epoch).call())

    def revoke(self, collector: str, epoch: int) -> dict:
        return self._send(self.contract.functions.revoke(self.b32(collector_key(collector)), epoch))
    def identity(self, collector: str, epoch: int) -> dict | None:
        key, sender, block, exists, recovery, policy_id = self.contract.functions.getEpoch(self.b32(collector_key(collector)), epoch).call()
        if not exists:
            return None
        from .protocol import Policy
        policy = next((name for name in ("P1", "B1", "B2", "B3", "B4", "A1", "A2", "A3", "A4", "A5", "FI", "FI-noerase", "FI-nochain")
                       if self.b32(digest("PABLA-POLICY-v1", name)) == bytes(policy_id)), None)
        witness_address = self.contract.functions.fiWitness(self.b32(collector_key(collector)),epoch).call() if policy in ("FI", "FI-noerase", "FI-nochain") else None
        return {"public_key": bytes(key).hex(), "revoked_block": int(block), "recovery": bytes(recovery).hex(), "policy": policy, "forward_integrity":policy in ("FI", "FI-noerase", "FI-nochain"),"witness_address": witness_address}
    def _anchor_args(self,batch: Batch):
        m=batch.manifest
        return (self.b32(collector_key(m["collector_id"])), m["epoch"],m["batch_number"],
              self.b32(batch.manifest_digest),self.b32(m["merkle_root"]),self.b32(m["last_chain"]),
              m["first_sequence"],m["last_sequence"],self.b32(m["previous_manifest_hash"]))

    def anchor(self, batch: Batch) -> dict:
        """Collector-only submission. It cannot pass witness-protected FI epochs."""
        m=batch.manifest
        args=self._anchor_args(batch)
        if "period" in m:
            return self._send(self.contract.functions.anchorFI(*args,m["period"],self.b32(m["schedule_root"])))
        return self._send(self.contract.functions.anchor(*args))

    def anchor_attested(self, batch: Batch, *, witness_signature: str) -> dict:
        """Witness-only submission after off-chain custody and signature checks.

        Only the separately trusted witness EVM account can send this call.
        Anvil's unlocked accounts are for tests, not an operational HSM.
        """
        from .protocol import valid_signature
        m=batch.manifest
        entry=getattr(self,'_witness_settings',{}).get((m['collector_id'],m['epoch']))
        if entry is None:
            raise ProtocolError('no separately registered FI witness')
        witness_public_key,witness_sender=entry
        if not valid_signature(witness_public_key,batch.manifest_digest,witness_signature):
            raise ProtocolError('witness attestation missing or invalid')
        args=self._anchor_args(batch)
        if 'period' not in m:
            raise ProtocolError('witness path requires forward-integrity batch')
        fn=self.contract.functions.anchorFIWitness(*args,m['period'],self.b32(m['schedule_root']))
        try:
            from web3.exceptions import ContractCustomError, ContractLogicError, TimeExhausted
            txid=fn.transact({'from':witness_sender})
            receipt=self.web3.eth.wait_for_transaction_receipt(txid, timeout=self.timeout_seconds)
        except (ContractCustomError,ContractLogicError,TimeExhausted,ValueError) as exc:
            raise ProtocolError(f'witness anchor failed: {type(exc).__name__}: {exc}') from exc
        if receipt['status'] != 1:
            raise ProtocolError('reverted FI witness anchor')
        self.calls+=1
        block=self.web3.eth.get_block(receipt['blockNumber'])
        txinput=self.web3.eth.get_transaction(txid)['input']
        return {'block_number':int(receipt['blockNumber']),'block_timestamp':float(block['timestamp']),
                'tx_hash':txid.hex(),'gas_used':int(receipt['gasUsed']),
                'transaction_input_bytes':len(bytes(txinput)) if isinstance(txinput,bytes) else len(bytes.fromhex(txinput.removeprefix('0x')))}

    def anchor_record(self, collector: str, epoch: int, batch_number: int) -> dict | None:
        mh, root, last, first, end, block, ts = self.contract.functions.getAnchor(
            self.b32(collector_key(collector)), epoch, batch_number).call()
        if block == 0:
            return None
        record={"manifest_hash": bytes(mh).hex(), "merkle_root": bytes(root).hex(),
                "last_chain": bytes(last).hex(), "first_sequence": int(first),
                "last_sequence": int(end), "block_number": int(block), "block_timestamp": float(ts)}
        period, schedule_root=self.contract.functions.getFIAnchor(self.b32(collector_key(collector)),epoch,batch_number).call()
        if period:
            record.update(period=int(period),schedule_root=bytes(schedule_root).hex())
        return record

    def latest(self, collector: str, epoch: int) -> tuple[int, int]:
        key = self.b32(collector_key(collector))
        return (int(self.contract.functions.latestBatch(key, epoch).call()),
                int(self.contract.functions.latestSequence(key, epoch).call()))
