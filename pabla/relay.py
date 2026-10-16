"""Independent, append-only custody simulation for signed but unanchored batches.

A receipt only exists at delivery time. A malicious collector can prevent future
emission or transmission; this module does not guarantee eventual delivery.
"""
from __future__ import annotations
from dataclasses import dataclass
from .protocol import Batch, Policy, Verdict, verify_pending_batch, ProtocolError, canonical, digest, keypair, sign
import copy

@dataclass(frozen=True)
class RelayReceipt:
    collector_id: str
    epoch: int
    batch_number: int
    manifest_digest: str
    emitted_ms: int
    delivered_ms: int

class WitnessRelay:
    def __init__(self, *, delivery_delay_ms: int = 0):
        if type(delivery_delay_ms) is not int or delivery_delay_ms < 0:
            raise ValueError('relay delay must be a nonnegative integer')
        self.delivery_delay_ms = delivery_delay_ms
        self._queue: list[tuple[RelayReceipt, Batch]] = []
        self._receipts: dict[tuple[str,int,int], tuple[RelayReceipt, Batch]] = {}
        self.conflicts: list[tuple[RelayReceipt, RelayReceipt]] = []
        self.__witness_key, self.public_key = keypair()

    def emit(self, batch: Batch, *, emitted_ms: int) -> RelayReceipt:
        if type(emitted_ms) is not int or emitted_ms < 0:
            raise ValueError('emission time must be nonnegative integer')
        m=batch.manifest
        receipt=RelayReceipt(m['collector_id'],m['epoch'],m['batch_number'],batch.manifest_digest,
                             emitted_ms, emitted_ms+self.delivery_delay_ms)
        self._queue.append((receipt,copy.deepcopy(batch)))
        return receipt

    def deliver(self, now_ms: int) -> list[RelayReceipt]:
        if type(now_ms) is not int or now_ms < 0:
            raise ValueError('invalid delivery time')
        arrived=[];remaining=[]
        for receipt, batch in self._queue:
            if receipt.delivered_ms > now_ms:
                remaining.append((receipt,batch));continue
            key=(receipt.collector_id,receipt.epoch,receipt.batch_number)
            previous=self._receipts.get(key)
            if previous and previous[0].manifest_digest != receipt.manifest_digest:
                self.conflicts.append((previous[0],receipt))
            elif previous is None:
                self._receipts[key]=(receipt,batch)
            arrived.append(receipt)
        self._queue=remaining
        return arrived

    def held(self, collector: str, epoch: int, batch_number: int) -> Batch | None:
        record=self._receipts.get((collector,epoch,batch_number))
        return copy.deepcopy(record[1]) if record else None

    def verify_held(self, collector: str, epoch: int, batch_number: int, *, ledger,
                    policy: Policy, previous: dict | None) -> Verdict | None:
        batch=self.held(collector,epoch,batch_number)
        return verify_pending_batch(batch,ledger,policy=policy,previous=previous) if batch else None

    def anchor_held(self, collector: str, epoch: int, batch_number: int, *, ledger,
                    policy: Policy, previous: dict | None) -> dict:
        """Commit only independently received, fully validated original evidence.

        The relay signs the manifest digest of the exact artifact in custody.
        Its key must be registered as an independent witness on the ledger.
        This deliberately does not allow a collector to supply an arbitrary
        caller-chosen manifest to be anchored. A missing receipt causes an
        availability failure, never silent approval of a competing commitment.
        """
        held = self.held(collector, epoch, batch_number)
        if held is None:
            raise ProtocolError('no independently delivered witness copy')
        checked = self.verify_held(collector, epoch, batch_number, ledger=ledger,
                                   policy=policy, previous=previous)
        if checked is None or checked.status not in ('ACCEPT', 'ACCEPT_WITH_WARNING'):
            raise ProtocolError(f'witness refuses invalid batch: {checked}')
        signature = sign(self.__witness_key, held.manifest_digest)
        return ledger.anchor_attested(held, witness_signature=signature)
