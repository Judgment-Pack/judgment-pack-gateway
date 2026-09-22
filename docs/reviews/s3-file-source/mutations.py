import pathlib, tempfile, json, subprocess, os
root=pathlib.Path(__file__).resolve().parents[3]/'adapters';work=pathlib.Path(tempfile.mkdtemp(prefix='jpack-s3-mutations-'))
checks=[
 ('grant-epoch','s3.go',' || g.S3.Epoch != epoch','', 'TestS3BrowseGrantExpiryPolicyAndScopeReplacement'),
 ('grant-expiry','s3.go',' || g.Expires <= time.Now().Unix()','', 'TestS3BrowseGrantExpiryPolicyAndScopeReplacement'),
 ('cursor-query','s3.go',' || browse.Query != q.Query','', 'TestS3PaginationContextAndSelectionIsolation'),
 ('conditional-header','s3_network.go','req.Header.Set("If-Match", etag)','_ = etag', 'TestS3SignedReadRetainsBytesAndConsumesGrant'),
 ('single-use','s3.go','if e = s.root.Remove("grant-" + q.Grant); e != nil {','if e = error(nil); e != nil {', 'TestS3SignedReadRetainsBytesAndConsumesGrant'),
 ('null-version','s3_network.go','if obj.Version != "" {','if obj.Version != "" && obj.Version != "null" {', 'TestS3NullVersionIsPinned'),
 ('after-fetch-disconnect','s3.go','if v.S3 == nil || v.Connection == nil || v.Connection.ID != c.ID || v.Epoch != epoch {','if false {', 'TestS3DisconnectDuringFetchAndConfigureWins'),
]
results=[]
for name,file,old,new,test in checks:
 path=root/'connections'/file;source=path.read_text()
 if source.count(old)!=1:raise RuntimeError((name,source.count(old)))
 changed=work/(name+'.go');changed.write_text(source.replace(old,new));overlay=work/(name+'.json');overlay.write_text(json.dumps({'Replace':{str(path):str(changed)}}))
 p=subprocess.run(['go','test','-overlay',str(overlay),'./connections','-run','^'+test+'$','-count=1'],cwd=root,env={**os.environ,'GOCACHE':os.environ.get('GOCACHE','/tmp/jpack-s3-mutation-cache')},text=True,capture_output=True)
 (work/(name+'.log')).write_text(p.stdout+p.stderr)
 # A compile failure is not a killed behavioral mutation.
 killed=p.returncode!=0 and ('--- FAIL:' in p.stdout or 'panic: runtime error:' in p.stdout)
 results.append({'guard':name,'caught':killed});print(name,killed,flush=True)
(work/'results.json').write_text(json.dumps(results,indent=2)+'\n')
if not all(r['caught'] for r in results):raise SystemExit(1)
