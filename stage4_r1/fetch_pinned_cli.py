#!/usr/bin/env python3
"""Stage 3 official npm integrity path reused for R1; runs ONLY after separate approval."""
import base64, hashlib, json, os, pathlib, tarfile, urllib.request
ROOT=pathlib.Path(__file__).resolve().parent
PIN=json.loads((ROOT/'STAGE3_PROVENANCE.json').read_text())
DEST=pathlib.Path(os.environ['R1_BIN_DIR']); DEST.mkdir(parents=True,exist_ok=True)
E=pathlib.Path(os.environ['R1_EVIDENCE_DIR']);E.mkdir(parents=True,exist_ok=True)
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,req,fp,code,msg,headers,newurl): raise RuntimeError('REDIRECT_DENIED')
fetcher=urllib.request.build_opener(NoRedirect)
def read_https(url,cap):
 if url not in {PIN['meta_url'],PIN['tarball_url']}:raise RuntimeError('HOST_OR_PATH_DENIED')
 with fetcher.open(urllib.request.Request(url,headers={'User-Agent':'pcc-r1-v2-pinned/1.0'}),timeout=40) as r:
  if r.status!=200: raise RuntimeError('HTTP_NON_200')
  data=r.read(cap+1)
 if len(data)>cap:raise RuntimeError('SIZE_LIMIT')
 return data
metadata=read_https(PIN['meta_url'],1024*1024)
obj=json.loads(metadata)
if (obj.get('name'),obj.get('version'))!=(PIN['npm_name'],PIN['cli_version']): raise RuntimeError('NPM_NAME_OR_VERSION_MISMATCH')
d=obj.get('dist',{})
if (d.get('integrity'),d.get('shasum'),d.get('tarball'))!=(PIN['npm_sha512_sri'],PIN['npm_sha1'],PIN['tarball_url']):raise RuntimeError('NPM_METADATA_MISMATCH')
tar=read_https(PIN['tarball_url'],180*1024*1024)
checks={
 'sri':'sha512-'+base64.b64encode(hashlib.sha512(tar).digest()).decode(),
 'sha1':hashlib.sha1(tar).hexdigest(), 'sha256':hashlib.sha256(tar).hexdigest()}
if (checks['sri'],checks['sha1'],checks['sha256'])!=(PIN['npm_sha512_sri'],PIN['npm_sha1'],PIN['tarball_sha256']):raise RuntimeError('TARBALL_DIGEST_MISMATCH')
import io
with tarfile.open(fileobj=io.BytesIO(tar),mode='r:gz') as tf:
 members=tf.getmembers()
 if len(members)>100:raise RuntimeError('TOO_MANY_TAR_MEMBERS')
 needed={'package/bin/opencode','package/package.json'}; found={}
 for m in members:
  p=pathlib.PurePosixPath(m.name)
  if p.is_absolute() or '..' in p.parts or not m.name.startswith('package/') or not(m.isfile() or m.isdir()):raise RuntimeError('UNSAFE_TAR_MEMBER')
  if m.isfile() and m.name in needed:
   if m.name in found:raise RuntimeError('DUPLICATE_TAR_ENTRY')
   if m.size>(240*1024*1024 if m.name.endswith('/opencode') else 65536):raise RuntimeError('TAR_ENTRY_TOO_BIG')
   found[m.name]=tf.extractfile(m).read()
 if set(found)!=needed:raise RuntimeError('MISSING_REQUIRED_ENTRY')
cli=found['package/bin/opencode'];pkg=found['package/package.json']
if hashlib.sha256(cli).hexdigest()!=PIN['cli_elf_sha256']:raise RuntimeError('ELF_DIGEST_MISMATCH')
pkgobj=json.loads(pkg)
if (pkgobj.get('name'),pkgobj.get('version'))!=(PIN['npm_name'],PIN['cli_version']):raise RuntimeError('PACKAGE_MISMATCH')
(DEST/'opencode').write_bytes(cli);(DEST/'opencode').chmod(0o755)
(DEST/'package.json').write_bytes(pkg)
(E/'supply_chain.json').write_text(json.dumps({'status':'PASS','tarball_sha256':checks['sha256'],'cli_sha256':PIN['cli_elf_sha256'],'version':PIN['cli_version']},indent=2)+'\n')
print('PINNED_NPM_AND_ELF_VERIFIED')
