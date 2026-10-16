"""Deploy compiled PABLA contract to local Anvil (localhost:8545)."""
import argparse
import json
from pathlib import Path
from web3 import Web3


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--rpc', default='http://127.0.0.1:8545')
    parser.add_argument('--artifact', default='contracts/out/CollectorAnchorRegistry.sol/CollectorAnchorRegistry.json')
    parser.add_argument('--out', default='contract-deployment.json')
    args = parser.parse_args()
    w3 = Web3(Web3.HTTPProvider(args.rpc))
    if not w3.is_connected() or w3.eth.chain_id != 31337:
        raise SystemExit('Local Anvil (chain ID 31337) required')
    artifact = json.loads(Path(args.artifact).read_text())
    contract = w3.eth.contract(abi=artifact['abi'], bytecode=artifact['bytecode']['object'])
    tx = contract.constructor().transact({'from':w3.eth.accounts[0]})
    receipt = w3.eth.wait_for_transaction_receipt(tx, timeout=120)
    if receipt.status != 1:
        raise SystemExit('Contract deployment reverted')
    result = {'backend':'anvil-evm', 'rpc': args.rpc,'address':receipt.contractAddress,
              'block_number':receipt.blockNumber,'tx_hash':tx.hex(), 'artifact':args.artifact}
    Path(args.out).write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result, indent=2))

if __name__ == '__main__':
    main()
