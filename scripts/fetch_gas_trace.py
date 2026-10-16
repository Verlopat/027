"""Export true mainnet base fees through authenticated bq CLI, not fabricated prices."""
from __future__ import annotations
import argparse,hashlib,json,shutil,subprocess
from pathlib import Path

def main():
    a=argparse.ArgumentParser()
    a.add_argument('--start',required=True,help='inclusive ISO date YYYY-MM-DD')
    a.add_argument('--end',required=True,help='exclusive ISO date YYYY-MM-DD')
    a.add_argument('--output',required=True)
    args=a.parse_args()
    if not shutil.which('bq'):
        print(json.dumps({'status':'not_run','reason':'bq CLI unavailable; a Google Cloud project is required'}))
        return 2
    from datetime import date
    date.fromisoformat(args.start);date.fromisoformat(args.end)
    if args.start>=args.end:raise ValueError('end must be later')
    query=f"SELECT number, timestamp, base_fee_per_gas FROM `bigquery-public-data.crypto_ethereum.blocks` WHERE DATE(timestamp) >= DATE('{args.start}') AND DATE(timestamp) < DATE('{args.end}') AND base_fee_per_gas IS NOT NULL ORDER BY number"
    proc=subprocess.run(['bq','query','--use_legacy_sql=false','--format=csv','--max_rows=1000000',query],capture_output=True,text=True,timeout=300)
    if proc.returncode:
        print(json.dumps({'status':'not_run','reason':'bq export failed','error':proc.stderr[-900:]}))
        return 2
    if not proc.stdout.strip():raise RuntimeError('query returned no rows')
    path=Path(args.output);path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(proc.stdout)
    manifest={'status':'ok','sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
              'query':query,'source':'bigquery-public-data.crypto_ethereum.blocks','date_start':args.start,'date_end':args.end}
    path.with_suffix('.manifest.json').write_text(json.dumps(manifest,indent=2))
    print(json.dumps(manifest))
    return 0
if __name__=='__main__':raise SystemExit(main())
