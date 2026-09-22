import json, pathlib, shutil, subprocess, os, hashlib
root=pathlib.Path(__file__).resolve().parents[2]; work=pathlib.Path(os.environ['S3_SMOKE_WORK']); work.mkdir(parents=True,exist_ok=True); bundle=work/'bundle'
shutil.copytree(os.environ['DESK_BUNDLE'],bundle,dirs_exist_ok=True)
info=json.loads(pathlib.Path(os.environ['JPACK_S3_SMOKE_READY']).read_text())
source=(root/'adapters/connections/s3.go').read_text().replace('p.client.Transport.(*http.Transport).DisableCompression = true','p.client.Transport.(*http.Transport).DisableCompression = true\n s3SmokeTransport(p.client)')
(work/'s3.go').write_text(source)
code='''package connections
import("context";"crypto/x509";"net";"net/http";"time")
func s3SmokeTransport(client *http.Client){
 transport:=client.Transport.(*http.Transport)
 roots:=x509.NewCertPool();roots.AppendCertsFromPEM([]byte(CERT))
 transport.TLSClientConfig.RootCAs=roots;transport.TLSClientConfig.ServerName=NAME
 transport.DialContext=func(ctx context.Context,network,addr string)(net.Conn,error){return (&net.Dialer{Timeout:5*time.Second}).DialContext(ctx,network,ADDR)}
}
'''.replace('CERT',json.dumps(info['certificate'])).replace('NAME',json.dumps(info['serverName'])).replace('ADDR',json.dumps(info['address']))
# Default transport has nil TLS config. Allocate in this test-only overlay.
code=code.replace('"context";','"context";"crypto/tls";').replace('roots:=x509.NewCertPool();','transport.TLSClientConfig=&tls.Config{MinVersion:tls.VersionTLS12};roots:=x509.NewCertPool();')
(work/'transport.go').write_text(code)
overlay={'Replace':{str(root/'adapters/connections/s3.go'):str(work/'s3.go'),str(root/'adapters/connections/s3_smoke_transport.go'):str(work/'transport.go')}}
(work/'overlay.json').write_text(json.dumps(overlay))
env={**os.environ,'GOCACHE':os.environ.get('GOCACHE','/tmp/jp-s3-build-cache')}
for name in ['gateway-connections','adapter-sources']:
 subprocess.run(['go','build','-buildvcs=false','-trimpath','-overlay',str(work/'overlay.json'),'-o',str(bundle/name),'./cmd/'+name],cwd=root/'adapters',env=env,check=True)
manifest=json.loads((bundle/'gateway-bundle.json').read_text());manifest['revision']='synthetic-s3-transport'
for name in ['gateway-connections','adapter-sources']:manifest['files'][name]=hashlib.sha256((bundle/name).read_bytes()).hexdigest()
(bundle/'gateway-bundle.json').write_text(json.dumps(manifest,indent=2)+'\n')
print('Synthetic S3 transport bundle ready; Desk unchanged:',hashlib.sha256((bundle/'jpack-desk').read_bytes()).hexdigest())
