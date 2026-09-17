"""Structurally decode, select/scale BAL records, then canonically encode them."""
import pathlib,json,hashlib,copy,sys
root=pathlib.Path(sys.argv[1]) if len(sys.argv)>1 else pathlib.Path(__file__).parent/'corpus'
def dec(b,i=0):
 x=b[i];i+=1
 if x<128:return bytes([x]),i
 if x<=183:n=x-128;return b[i:i+n],i+n
 if x<192:k=x-183;n=int.from_bytes(b[i:i+k],'big');i+=k;return b[i:i+n],i+n
 if x<=247:n=x-192
 else:k=x-247;n=int.from_bytes(b[i:i+k],'big');i+=k
 end=i+n;v=[]
 while i<end:t,i=dec(b,i);v.append(t)
 assert i==end
 return v,i
def enc(x):
 if isinstance(x,bytes):
  if len(x)==1 and x[0]<128:return x
  p=x;off=128
 else:p=b''.join(map(enc,x));off=192
 n=len(p)
 if n<56:return bytes([off+n])+p
 k=n.to_bytes((n.bit_length()+7)//8,'big');return bytes([off+55+len(k)])+k+p
def stats(x):
 return dict(accounts=len(x),read_slots=sum(len(a[2]) for a in x),write_slots=sum(len(a[1]) for a in x),storage_changes=sum(len(s[1]) for a in x for s in a[1]),balance_changes=sum(len(a[3]) for a in x),nonce_changes=sum(len(a[4]) for a in x),code_changes=sum(len(a[5]) for a in x),max_index=max([int.from_bytes(c[0],'big') for a in x for c in [*(c for s in a[1] for c in s[1]),*a[3],*a[4],*a[5]]],default=0))
man=[r for r in json.load(open(root/'manifest.json')) if not r.get('synthetic')]
for r in man:
 raw=(root/(r['id']+'.rlp')).read_bytes();x,end=dec(raw);assert end==len(raw) and enc(x)==raw;r.update(stats(x))
base,_=dec((root/'300M-25912202.rlp').read_bytes())
def save(name,x):
 x=[copy.deepcopy(a) for a in x]
 # Stable fresh unique addresses, preserving canonical order and all original histories.
 for i,a in enumerate(x):a[0]=(i+1).to_bytes(20,'big')
 raw=enc(x);(root/(name+'.rlp')).write_bytes(raw)
 man.append(dict(id=name,synthetic=True,source='300M-25912202',bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),synthetic_tx_count=stats(x)["max_index"],access_index_bound=stats(x)["max_index"]+1,**stats(x)))
for n in [1,4,16,64,256,1024]:save(f'scaled-accounts-{n}',base[:n])
for factor in [2,4]:save(f'scaled-{factor}x',base*factor)
for shape in ['read','write','code','many-small','few-large']:
 for target in [4096,65536,1048576,4194304]:
  if shape=='read':
   x=[[b'',[],[i.to_bytes((i.bit_length()+7)//8,'big') for i in range(max(1,target//33))],[],[],[]]]
  elif shape=='write':
   x=[[b'',[[i.to_bytes((i.bit_length()+7)//8,'big'),[[b'\x01',(i+1).to_bytes(((i+1).bit_length()+7)//8,'big')]]] for i in range(max(1,target//70))],[],[],[],[]]]
  elif shape=='code':x=[[b'',[],[],[],[],[[b'\x01',bytes([0x60])*min(24000,target-32)]]]]*max(1,target//24000)
  elif shape=='many-small':x=[[b'',[],[],[[b'\x01',b'\x01']],[],[]] for _ in range(target//30)]
  else:
   a=copy.deepcopy(max(base,key=lambda a:len(enc(a))))
   x=[a]*max(1,target//len(enc(a)))
  save(f'shape-{shape}-{target}',x)
(root/'manifest.json').write_text(json.dumps(man,indent=2)+'\n')
print(len(man),'cases',sum(r['bytes'] for r in man),'bytes')
