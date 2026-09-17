import json,hashlib,pathlib,sys
out=pathlib.Path(sys.argv[2]) if len(sys.argv)>2 else pathlib.Path(__file__).parent/'corpus';out.mkdir(exist_ok=True)
manifest=[]
for label,run in [('200M','35126507171'),('300M','35151583457')]:
 root=pathlib.Path(sys.argv[1])/run
 src=root/'txgen-payloads/measured-big-blocks.ndjson'
 sha=hashlib.sha256(src.read_bytes()).hexdigest()
 blocks={b['number']:b for b in json.load(open(root/'baseline-1/report.json'))['blocks']}
 for row in map(json.loads,src.open()):
  raw=bytes.fromhex(row['merged_block_access_list'].removeprefix('0x'))
  name=f"{label}-{row['block_number']}";(out/(name+'.rlp')).write_bytes(raw)
  b=blocks[row['block_number']]
  manifest.append(dict(id=name,source_run=run,source_sha256=sha,sha256=hashlib.sha256(raw).hexdigest(),bytes=len(raw),block_number=row['block_number'],gas_used=b['gas_used'],gas_limit=b['gas_limit'],tx_count=b['tx_count'],environment_count=len(row['env_switches']),access_index_bound=b['tx_count']+2*len(row['env_switches'])-1))
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
for label in ['200M','300M']:
 rows=[r for r in manifest if r['id'].startswith(label)]
 print(label,len(rows),'bytes',min(r['bytes'] for r in rows),max(r['bytes'] for r in rows),'gas',min(r['gas_used'] for r in rows),max(r['gas_used'] for r in rows))
