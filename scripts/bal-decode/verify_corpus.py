"""Check canonical round trips, ordering, uniqueness, and recorded corpus hashes."""
import hashlib,json,pathlib,runpy,sys
# Load only parser/encoder definitions; do not regenerate inputs while verifying them.
namespace={'__file__':str(pathlib.Path(__file__).with_name('synthetic.py'))}
source=pathlib.Path(__file__).with_name('synthetic.py').read_text()
exec(source.split('man=[r')[0],namespace)
root=pathlib.Path(sys.argv[1]);dec=namespace['dec'];enc=namespace['enc']
expected={r['id']:r for r in json.load(pathlib.Path(__file__).with_name('results').joinpath('manifest.json').open())}
rows=json.load((root/'manifest.json').open())
assert {r['id'] for r in rows}==set(expected)
for row in rows:
 assert row['sha256']==expected[row['id']]['sha256'] and row['bytes']==expected[row['id']]['bytes']
 raw=(root/(row['id']+'.rlp')).read_bytes();bal,end=dec(raw)
 assert len(raw)==row['bytes'] and hashlib.sha256(raw).hexdigest()==row['sha256']
 assert end==len(raw) and enc(bal)==raw
 assert [a[0] for a in bal]==sorted(set(a[0] for a in bal))
 for a in bal:
  assert len(a)==6 and len(a[0])==20
  slots=[int.from_bytes(s[0],'big') for s in a[1]];reads=[int.from_bytes(s,'big') for s in a[2]]
  assert slots==sorted(set(slots)) and reads==sorted(set(reads)) and not set(slots)&set(reads)
  for changes in [*(s[1] for s in a[1]),a[3],a[4],a[5]]:
   ids=[int.from_bytes(c[0],'big') for c in changes]
   assert ids==sorted(set(ids)) and all(i<=row['access_index_bound'] for i in ids)
print('Corpus hashes, round trips, ordering, uniqueness and index bounds verified.')
