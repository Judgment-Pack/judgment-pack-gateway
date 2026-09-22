import {createRequire} from 'node:module';
import {mkdir,cp,readFile,writeFile} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {createHash,randomBytes} from 'node:crypto';
const {S3_SMOKE_WORK:work,DESK_BUNDLE,DESK_CHECKOUT,JPACK_FIXTURE_PROJECT,JPACK_BINARY,CHROMIUM_PATH}=process.env;
if(!work||!DESK_BUNDLE||!DESK_CHECKOUT||!JPACK_FIXTURE_PROJECT||!JPACK_BINARY||!CHROMIUM_PATH)throw Error('Missing smoke environment');
const bundle=work+'/bundle';
const hash=x=>createHash('sha256').update(x).digest('hex');
const secret=randomBytes(24).toString('hex');
await cp(JPACK_FIXTURE_PROJECT,work+'/project',{recursive:true});
for(const dir of ['config','data','evidence'])await mkdir(work+'/'+dir,{recursive:true});
const origin='http://127.0.0.1:18923';
const server=spawn(bundle+'/jpack-desk',['--port','18923','--dev-token',secret,'--print-url=false','--jpack',JPACK_BINARY,work+'/project'],{env:{...process.env,XDG_CONFIG_HOME:work+'/config',XDG_DATA_HOME:work+'/data',JPACK_DESK_GATEWAY_MANIFEST_SHA256:hash(await readFile(bundle+'/gateway-bundle.json'))},stdio:'ignore'});
const api=(path,init={})=>fetch(origin+path,{...init,headers:{Authorization:`Bearer ${secret}`,...init.headers}});
const {chromium}=createRequire(DESK_CHECKOUT+'/web/package.json')('playwright-core');
let browser,page;const result={};
try{
 for(let i=0;i<150;i++){try{if((await api('/api/conversations')).ok)break}catch{}await new Promise(r=>setTimeout(r,100))}
 browser=await chromium.launch({executablePath:CHROMIUM_PATH,args:['--no-sandbox']});page=await browser.newPage({colorScheme:'dark',viewport:{width:1440,height:1000}});page.setDefaultTimeout(20000);
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.route('**/api/desk-config',async route=>{const response=await route.fetch();const data=await response.json();data.present=true;data.content=JSON.stringify({deskConfigVersion:1,assistant:{endpoint:{url:'https://model.invalid/v1',kind:'openai-compatible',model:'synthetic-model',models:['synthetic-model'],tools:['validate']}}});await route.fulfill({response,json:data})});
 await page.goto(origin+'/launch?secret='+secret);
 const composer=page.getByRole('textbox',{name:'Message the assistant',exact:true});await composer.fill('Keep my draft while selecting S3 files.');
 async function openS3(){await page.getByRole('button',{name:'Attach files',exact:true}).click();await page.getByRole('menuitem',{name:'More connections',exact:true}).click();await page.getByRole('button',{name:/Amazon S3/}).click()}
 await openS3();const pane=page.locator('#desk-inspector');
 await pane.getByLabel('AWS region',{exact:true}).fill('ca-central-1');await pane.getByLabel('Bucket',{exact:true}).fill('example-bucket');await pane.getByLabel('Prefix (optional)',{exact:true}).fill('policies/');await pane.getByLabel('Access key ID',{exact:true}).fill('AKIAIOSFODNN7EXAMPLE');await pane.getByLabel('Secret access key',{exact:true}).fill('wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY');
 await page.screenshot({path:work+'/evidence/setup.png'});await pane.getByRole('button',{name:'Save',exact:true}).click();
 await pane.getByText('example-bucket/policies/',{exact:true}).first().waitFor();result.scope=true;
 await pane.getByRole('button',{name:'Next page',exact:true}).click();
 await pane.getByRole('checkbox',{name:/policies\/a.txt/}).check();await pane.getByRole('checkbox',{name:/policies\/document.pdf/}).check();result.pagination=true;
 await page.screenshot({path:work+'/evidence/select.png'});await pane.getByRole('button',{name:'Attach 2 items',exact:true}).click();
 await page.getByRole('button',{name:'a.txt',exact:true}).waitFor();await page.getByRole('button',{name:'document.pdf',exact:true}).waitFor();
 result.draftPreserved=await composer.inputValue()==='Keep my draft while selecting S3 files.';result.focus=await composer.evaluate(x=>document.activeElement===x);
 await page.getByRole('button',{name:'a.txt',exact:true}).click();const text=page.getByRole('dialog',{name:'a.txt',exact:true});await text.getByText(/Receipt verified/).waitFor();await text.getByText('S3 fixture policy: reimburse approved travel.',{exact:true}).waitFor();result.textVerified=true;await page.screenshot({path:work+'/evidence/verified-text.png'});await page.keyboard.press('Escape');
 await page.getByRole('button',{name:'document.pdf',exact:true}).click();await page.getByRole('dialog',{name:'document.pdf',exact:true}).getByText(/Receipt verified/).waitFor();result.pdfVerified=true;await page.screenshot({path:work+'/evidence/verified-pdf.png'});await page.keyboard.press('Escape');
 await openS3();await pane.getByText('Connection settings',{exact:true}).click();await pane.getByRole('button',{name:'Disconnect',exact:true}).click();await pane.getByText('Disconnected here. Provider access may still be active.',{exact:true}).waitFor();result.disconnectTruthful=true;
 result.deskUnchanged=hash(await readFile(bundle+'/jpack-desk'))===hash(await readFile(DESK_BUNDLE+'/jpack-desk'));result.unsentChats=(await(await api('/api/conversations')).json()).chats?.length??0;result.errors=errors;
 if(Object.values(result).some(x=>x===false)||result.unsentChats!==0||errors.length)throw Error('Acceptance failed');
 await writeFile(work+'/evidence/findings.json',JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result,null,2));
}catch(error){if(page){await page.screenshot({path:work+'/evidence/failure.png'});await writeFile(work+'/evidence/failure.txt',await page.locator('body').innerText())}throw error}
finally{await browser?.close();server.kill('SIGTERM')}
