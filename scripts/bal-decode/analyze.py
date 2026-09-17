"""Generate the complete per-case matrix and paired summary tables (stdlib only)."""
import collections,csv,json,math,pathlib,statistics,gzip
root=pathlib.Path(__file__).parent
results=root/'results'
manifest={r['id']:r for r in json.load((results/'manifest.json').open())}
all_rows=[];groups=[];tables=[]
def mean(xs):return statistics.mean(xs)
def ci(xs):
 n=len(xs);m=mean(xs);t=2.145 if n==15 else 2.228
 e=t*statistics.stdev(xs)/math.sqrt(n) if n>1 else 0
 return m,e
for stage in ['exploratory','followup','shared-match','shared-rest','shared-header']:
 rows=list(csv.DictReader(gzip.open(results/(stage+'.csv.gz'),'rt')))
 by=collections.defaultdict(dict)
 for r in rows:by[r['id'],r['strategy']][int(r['round'])]=r
 for (id,strategy),rs in by.items():
  bs=by[id,'baseline'];rounds=sorted(rs.keys()&bs.keys());assert len(rounds) in [11,15],(stage,id,strategy,len(rounds))
  delta=[100*(float(rs[k]['decode_ns'])/float(bs[k]['decode_ns'])-1) for k in rounds]
  m,e=ci(delta);ns=mean(float(rs[k]['decode_ns']) for k in rounds);life=mean(float(rs[k]['lifecycle_ns']) for k in rounds)
  all_rows.append(dict(stage=stage,id=id,bytes=manifest[id]['bytes'],strategy=strategy,rounds=len(rounds),decode_ns=ns,lifecycle_ns=life,bytes_per_second=manifest[id]['bytes']*1e9/ns,paired_percent=m,ci95_low=m-e,ci95_high=m+e,allocations=rs[rounds[0]]['allocs'],allocated_bytes=rs[rounds[0]]['allocated_bytes']))
 strategies=list(dict.fromkeys(r['strategy'] for r in rows))
 for label in ['200M','300M']:
  ids=[id for id in manifest if id.startswith(label)]
  for strategy in strategies:
   ks=sorted(by[ids[0],strategy]);delta=[];ns=[];life=[];life_delta=[]
   for k in ks:
    b=mean(float(by[id,'baseline'][k]['decode_ns']) for id in ids);v=mean(float(by[id,strategy][k]['decode_ns']) for id in ids)
    l=mean(float(by[id,strategy][k]['lifecycle_ns']) for id in ids);lb=mean(float(by[id,'baseline'][k]['lifecycle_ns']) for id in ids)
    delta.append(100*(v/b-1));ns.append(v);life.append(l);life_delta.append(100*(l/lb-1))
   m,e=ci(delta);groups.append(dict(stage=stage,group=label,strategy=strategy,decode_ns=mean(ns),lifecycle_ns=mean(life),paired_percent=m,ci95_low=m-e,ci95_high=m+e,lifecycle_percent=mean(life_delta)))
for name,rows in [('matrix',all_rows),('summary',groups)]:
 with (results/(name+'.csv')).open('w') as f:
  w=csv.DictWriter(f,fieldnames=list(rows[0]),lineterminator="\n");w.writeheader();w.writerows(rows)
lines=['# Generated benchmark tables','','Negative changes mean faster. Intervals are paired 95% t intervals over repeated runs of the same corpus, not workload-generalization intervals.','']
for stage in dict.fromkeys(r['stage'] for r in groups):
 lines+=['## '+stage,'','| Strategy | 200M decode µs; change [95% CI] | 300M decode µs; change [95% CI] |','|---|---:|---:|']
 for strategy in dict.fromkeys(r['strategy'] for r in groups if r['stage']==stage):
  rr=[next(r for r in groups if r['stage']==stage and r['strategy']==strategy and r['group']==g) for g in ['200M','300M']]
  lines+=['| '+strategy+' | '+' | '.join(f"{r['decode_ns']/1000:.1f}; {r['paired_percent']:+.2f}% [{r['ci95_low']:+.2f}, {r['ci95_high']:+.2f}]" for r in rr)+' |']
 lines+=['']
lines+=['## Synthetic size/shape matrix','','Names retain generator target sizes; the bytes column is the actual encoded size. These are scaled workloads, not measured gas.','', '| Case | Bytes | Baseline µs | Count Δ [95% CI] | Estimate Δ | Hybrid Δ | Bounded Δ | Shared-rest Δ [95% CI] |','|---|---:|---:|---:|---:|---:|---:|---:|']
for id,info in manifest.items():
 if not info.get('synthetic'):continue
 def get(stage,s):return next(r for r in all_rows if r['id']==id and r['stage']==stage and r['strategy']==s)
 def delta(r,interval=False):return f"{r['paired_percent']:+.1f}%"+(f" [{r['ci95_low']:+.1f}, {r['ci95_high']:+.1f}]" if interval else '')
 b=get('exploratory','baseline');c=get('exploratory','count');shared=get('shared-rest','rest')
 lines+=['| '+id+f" | {info['bytes']:,} | {b['decode_ns']/1000:.2f} | "+delta(c,True)+' | '+' | '.join(delta(get('exploratory',s)) for s in ['estimate','hybrid256','bounded'])+' | '+delta(shared,True)+' |']
(results/'tables.md').write_text('\n'.join(lines)+'\n')
print('\n'.join(lines[:35]))
