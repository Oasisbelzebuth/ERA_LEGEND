'use strict';
/* ERA — serveur (aucune dépendance, Node 18+).  Lancer :  node server.js   (PORT=3000, ERA_ADMIN_CODE=OASIS par défaut)
   Fait : comptes (nom + code, hash scrypt), sauvegarde unique par compte, vérification du code admin, plafond niveau 300,
   et le serveur en ligne du Colisée (chat, positions, classement, duels) sur /ws.
   Variables : PORT, ERA_ADMIN_CODE, ERA_ORIGIN (adresse du jeu sur GitHub Pages), ERA_DATA (dossier des données, à placer sur un disque persistant).
   Pour publier : mets-le derrière HTTPS (Caddy, Nginx, Render, Railway…) — le jeu passe alors tout seul en wss://. */
const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const PORT=+process.env.PORT||3000;
const norm=s=>String(s||'').toUpperCase().replace(/[^A-Z0-9_-]/g,'');
const ADMIN=norm(process.env.ERA_ADMIN_CODE||'OASIS');
const DATA=process.env.ERA_DATA||path.join(__dirname,'data'),SAVES=path.join(DATA,'saves');fs.mkdirSync(SAVES,{recursive:true});
const jr=(f,d)=>{try{return JSON.parse(fs.readFileSync(f,'utf8'))}catch(e){return d}};
const jw=(f,o)=>{const t=f+'.tmp';fs.writeFileSync(t,JSON.stringify(o));fs.renameSync(t,f)};
const FA=path.join(DATA,'accounts.json'),FS=path.join(DATA,'sessions.json'),FB=path.join(DATA,'board.json');
let ACC=jr(FA,{}),SES=jr(FS,{}),BOARD=jr(FB,[]);
const now=()=>Date.now();let st=0;const flush=()=>{clearTimeout(st);st=setTimeout(()=>{jw(FA,ACC);jw(FS,SES)},300)};
for(const t in SES)if(SES[t].exp<now())delete SES[t];
// ---- plafond de niveau côté serveur (aucune zone bloquée)
const MAXLV=300,BLOCK=new Set();
const hashC=(c,salt)=>crypto.scryptSync(String(c),salt,32);
const okName=u=>/^[A-Za-z0-9_-]{3,16}$/.test(u||''),okCode=c=>typeof c=='string'&&c.length>=4&&c.length<=32;
const sp=u=>path.join(SAVES,u+'.json');
const loadLs=u=>(jr(sp(u),{ls:{}}).ls)||{};
function sane(ls){const out={};if(!ls||typeof ls!='object')return out;
 for(const k of Object.keys(ls)){if(!/^pl_[A-Za-z0-9_]{1,24}$/.test(k))continue;const v=ls[k];if(typeof v!='string'||v.length>1.5e6)continue;out[k]=v}
 if(out.pl_s0){try{const d=JSON.parse(out.pl_s0);if(d&&typeof d=='object'){d.lv=Math.max(1,Math.min(MAXLV,d.lv|0));if(d.lv>=MAXLV)d.xp=0;if(BLOCK.has(d.m)){d.m='forest';delete d.x;delete d.y}out.pl_s0=JSON.stringify(d)}else delete out.pl_s0}catch(e){delete out.pl_s0}}
 return out}
// ---- limitation des essais
const FAIL=new Map();const tooMany=k=>{const f=FAIL.get(k);return f&&f.n>=8&&now()-f.t<6e5};
const fail=k=>{const f=FAIL.get(k);if(!f||now()-f.t>=6e5)FAIL.set(k,{n:1,t:now()});else{f.n++;f.t=now()}};
// ---- HTTP
const body=req=>new Promise((res,rej)=>{let n=0;const a=[];req.on('data',c=>{n+=c.length;if(n>3e6){rej(new Error('big'));req.destroy()}else a.push(c)});req.on('end',()=>{try{res(JSON.parse(Buffer.concat(a).toString()||'{}'))}catch(e){res({})}});req.on('error',rej)});
const out=(res,s,o)=>{res.writeHead(s,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(JSON.stringify(o))};
const sess=req=>{const m=/^Bearer (\w{64})$/.exec(req.headers.authorization||'');const s=m&&SES[m[1]];return s&&s.exp>now()?{t:m[1],s}:null};
const newTok=u=>{const t=crypto.randomBytes(32).toString('hex');SES[t]={u,exp:now()+30*864e5};flush();return t};
async function api(req,res){
 const ip=req.socket.remoteAddress,p=req.url.split('?')[0],B=req.method=='GET'||req.method=='HEAD'?{}:await body(req);
 if(p=='/api/register'&&req.method=='POST'){const u=String(B.u||'').trim(),c=B.c;
  if(!okName(u))return out(res,400,{e:'Nom : 3 à 16 caractères (lettres, chiffres, - _)'});if(!okCode(c))return out(res,400,{e:'Code : 4 à 32 caractères'});
  const k=u.toLowerCase();if(ACC[k])return out(res,409,{e:'Ce nom est déjà pris'});
  if(tooMany('r|'+ip))return out(res,429,{e:'Trop d’essais, réessaie plus tard'});fail('r|'+ip);
  const salt=crypto.randomBytes(16).toString('hex');ACC[k]={name:u,salt,hash:hashC(c,salt).toString('hex'),created:now()};jw(sp(k),{ls:{}});flush();
  return out(res,200,{t:newTok(k),u,ls:{}})}
 if(p=='/api/login'&&req.method=='POST'){const u=String(B.u||'').trim(),k=u.toLowerCase(),f='l|'+ip+'|'+k;
  if(tooMany(f))return out(res,429,{e:'Trop d’essais, réessaie dans quelques minutes'});
  const a=ACC[k];let ok=false;if(a&&okCode(B.c)){const h=hashC(B.c,a.salt),g=Buffer.from(a.hash,'hex');ok=h.length==g.length&&crypto.timingSafeEqual(h,g)}
  if(!ok){fail(f);return out(res,401,{e:'Nom ou code incorrect'})}FAIL.delete(f);return out(res,200,{t:newTok(k),u:a.name,ls:loadLs(k)})}
 const S=sess(req);if(!S)return out(res,401,{e:'Session expirée'});const k=S.s.u,a=ACC[k];if(!a)return out(res,401,{e:'Compte introuvable'});
 if(p=='/api/me')return out(res,200,{u:a.name,ls:loadLs(k)});
 if(p=='/api/save'&&req.method=='PUT'){jw(sp(k),{ls:sane(B.ls),t:now()});return out(res,200,{ok:1})}
 if(p=='/api/hero'&&req.method=='DELETE'){jw(sp(k),{ls:{},t:now()});return out(res,200,{ok:1})}
 if(p=='/api/logout'){delete SES[S.t];flush();return out(res,200,{ok:1})}
 if(p=='/api/code'&&req.method=='POST'){const f='c|'+k;if(tooMany(f))return out(res,429,{e:'Trop d’essais'});
  const h=hashC(B.o,a.salt),g=Buffer.from(a.hash,'hex');if(!(h.length==g.length&&crypto.timingSafeEqual(h,g))){fail(f);return out(res,403,{e:'Ancien code incorrect'})}
  if(!okCode(B.n))return out(res,400,{e:'Nouveau code : 4 à 32 caractères'});a.salt=crypto.randomBytes(16).toString('hex');a.hash=hashC(B.n,a.salt).toString('hex');
  for(const t in SES)if(SES[t].u==k&&t!=S.t)delete SES[t];flush();return out(res,200,{ok:1})}
 if(p=='/api/account'&&req.method=='DELETE'){const h=hashC(B.c,a.salt),g=Buffer.from(a.hash,'hex');if(!(h.length==g.length&&crypto.timingSafeEqual(h,g)))return out(res,403,{e:'Code incorrect'});
  delete ACC[k];for(const t in SES)if(SES[t].u==k)delete SES[t];try{fs.unlinkSync(sp(k))}catch(e){}flush();return out(res,200,{ok:1})}
 if(p=='/api/admin'&&req.method=='POST'){const f='a|'+k;if(tooMany(f))return out(res,429,{e:'Trop d’essais'});
  if(norm(B.c)&&norm(B.c)===ADMIN){S.s.adm=1;flush();return out(res,200,{ok:1})}fail(f);return out(res,403,{ok:0})}
 out(res,404,{e:'Introuvable'})}
const ORIGIN=process.env.ERA_ORIGIN||'*'; // ex. https://ton-compte.github.io pour n'autoriser que ton jeu
const server=http.createServer((req,res)=>{
 res.setHeader('Access-Control-Allow-Origin',ORIGIN);res.setHeader('Access-Control-Allow-Headers','Content-Type, Authorization');res.setHeader('Access-Control-Allow-Methods','GET,POST,PUT,DELETE,OPTIONS');res.setHeader('Access-Control-Max-Age','86400');
 if(req.method=='OPTIONS'){res.writeHead(204);return res.end()}
 const p=req.url.split('?')[0];
 if(p.startsWith('/api/'))return api(req,res).catch(()=>out(res,500,{e:'Erreur serveur'}));
 if(p=='/'||p=='/index.html'){fs.readFile(path.join(__dirname,'index.html'),(e,d)=>{if(e){res.writeHead(500);return res.end('index.html manquant')}res.writeHead(200,{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-cache'});res.end(d)});return}
 res.writeHead(404);res.end('404')});
// ---- WebSocket (Colisée : chat, positions, classement, duels 1v1) — implémentation minimale RFC 6455
const GUID='258EAFA5-E914-47DA-95CA-C5AB0DC85B11',C=new Map(),HIST=[],QUEUE=[];let NID=1;
const enc=(o,op)=>{const p=op==10?Buffer.alloc(0):Buffer.from(JSON.stringify(o)),n=p.length;let h;
 if(n<126)h=Buffer.from([128|(op||1),n]);else if(n<65536){h=Buffer.alloc(4);h[0]=128|(op||1);h[1]=126;h.writeUInt16BE(n,2)}else{h=Buffer.alloc(10);h[0]=128|(op||1);h[1]=127;h.writeBigUInt64BE(BigInt(n),2)}return Buffer.concat([h,p])};
const tx=(c,o)=>{try{c.sock.write(enc(o))}catch(e){}};const all=(o,ex)=>{for(const c of C.values())if(c!==ex)tx(c,o)};
const num=(v,a,b)=>{v=+v;return isFinite(v)?Math.max(a,Math.min(b,v)):0};
const unq=c=>{const i=QUEUE.indexOf(c);if(i>=0)QUEUE.splice(i,1)};
const unpair=c=>{const o=c.partner;c.partner=null;if(o)o.partner=null;return o};
function onMsg(c,d){if(!d||typeof d.t!='string')return;if(++c.rate>80)return;
 switch(d.t){
  case'chat':{const m=String(d.m||'').slice(0,80).trim();if(!m)return;HIST.push({n:c.name,m});if(HIST.length>30)HIST.shift();all({t:'chat',n:c.name,m});break}
  case'pos':{const o={t:'pos',id:c.id,n:c.name,m:String(d.m||'').slice(0,12),x:num(d.x,-1e5,1e5),y:num(d.y,-1e5,1e5),fx:num(d.fx,-1,1),fy:num(d.fy,-1,1),mv:d.mv?1:0,sf:d.sf?1:0,pv:d.pv?1:0,hp:d.hp==null?100:num(d.hp,0,100)};
   if(d.a&&JSON.stringify(d.a).length<2000)o.a=d.a;if(d.tf&&JSON.stringify(d.tf).length<2000)o.tf=d.tf;c.pos=o;all(o,c);break}
  case'score':{const e=d.e||{};BOARD.push({n:c.name,l:String(e.l||'').slice(0,12),w:num(e.w,0,9999)|0,t:num(e.t,0,1e6)|0,win:e.win?1:0,d:now()});BOARD.sort((a,b)=>b.w-a.w||a.t-b.t);BOARD=BOARD.slice(0,8);jw(FB,BOARD);all({t:'board',board:BOARD});break}
  case'q':{unq(c);const code=String(d.c||'').trim().slice(0,12).toLowerCase(),app=d.a&&JSON.stringify(d.a).length<2000?d.a:{};c.app=app;
   const i=QUEUE.findIndex(q=>q.code==code&&q.c!==c&&!q.c.partner);
   if(i>=0){const o=QUEUE.splice(i,1)[0].c;c.partner=o;o.partner=c;tx(o,{t:'match',side:0,opp:{n:c.name,a:c.app}});tx(c,{t:'match',side:1,opp:{n:o.name,a:o.app}})}else QUEUE.push({c,code});break}
  case'qc':unq(c);break;
  case'de':{unq(c);const o=unpair(c);if(o)tx(o,{t:'dx'});break}
  case'dp':if(c.partner)tx(c.partner,{t:'dp',x:num(d.x,-1e5,1e5),y:num(d.y,-1e5,1e5),fx:num(d.fx,-1,1),fy:num(d.fy,-1,1),mv:d.mv?1:0,hp:num(d.hp,0,1e6),mx:num(d.mx,1,1e6)});break;
  case'dh':if(c.partner)tx(c.partner,{t:'dh',f:num(d.f,0,1),kx:num(d.kx,-9,9),ky:num(d.ky,-9,9)});break;
  case'dd':{const o=unpair(c);if(o)tx(o,{t:'dd'});break}
  case'ph':{const f=+d.f;if(!(f>0&&f<=.6))return;const o=C.get(+d.to);if(o&&o!==c)tx(o,{t:'ph',f,kx:num(d.kx,-9,9),ky:num(d.ky,-9,9)});break}}}
function drop(c){if(!C.delete(c.id))return;unq(c);const o=unpair(c);if(o)tx(o,{t:'dx'});all({t:'bye',id:c.id});all({t:'online',n:C.size})}
server.on('upgrade',(req,sock)=>{
 const u=new URL(req.url,'http://x'),t=u.searchParams.get('t')||'',s=SES[t],key=req.headers['sec-websocket-key'];
 if(u.pathname!='/ws'||!key||!s||s.exp<now()||!ACC[s.u]){sock.write('HTTP/1.1 401 Unauthorized\r\n\r\n');return sock.destroy()}
 for(const o of C.values())if(o.user==s.u){try{o.sock.destroy()}catch(e){}drop(o)}
 sock.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: '+crypto.createHash('sha1').update(key+GUID).digest('base64')+'\r\n\r\n');
 const c={id:NID++,sock,user:s.u,name:ACC[s.u].name,buf:Buffer.alloc(0),frag:[],rate:0,partner:null,pos:null,alive:1};C.set(c.id,c);
 tx(c,{t:'hello',board:BOARD,n:C.size,history:HIST,players:[...C.values()].filter(o=>o!==c&&o.pos).map(o=>o.pos)});all({t:'online',n:C.size},c);
 sock.on('data',b=>{c.buf=Buffer.concat([c.buf,b]);if(c.buf.length>2e5)return sock.destroy();
  while(c.buf.length>=2){const b0=c.buf[0],b1=c.buf[1],op=b0&15,fin=b0&128;let n=b1&127,off=2;
   if(n==126){if(c.buf.length<4)return;n=c.buf.readUInt16BE(2);off=4}else if(n==127){if(c.buf.length<10)return;n=Number(c.buf.readBigUInt64BE(2));off=10}
   if(n>65536)return sock.destroy();const mk=b1&128;if(mk)off+=4;if(c.buf.length<off+n)return;
   let p=c.buf.subarray(off,off+n);if(mk){const m=c.buf.subarray(off-4,off);p=Buffer.from(p.map((x,i)=>x^m[i&3]))}c.buf=c.buf.subarray(off+n);
   if(op==8){sock.end();return}if(op==9){try{sock.write(enc(null,10))}catch(e){}continue}if(op==10){c.alive=1;continue}
   if(op==1||op==0){c.frag.push(p);if(fin){let d=null;try{d=JSON.parse(Buffer.concat(c.frag).toString())}catch(e){}c.frag=[];onMsg(c,d)}}}});
 sock.on('close',()=>drop(c));sock.on('error',()=>{});});
setInterval(()=>{for(const c of C.values())c.rate=0},1000);
setInterval(()=>{for(const c of C.values()){if(!c.alive){try{c.sock.destroy()}catch(e){}drop(c);continue}c.alive=0;try{c.sock.write(Buffer.from([0x89,0]))}catch(e){}}},15e3);
server.listen(PORT,()=>console.log('ERA : http://localhost:'+PORT+'  (code admin : variable ERA_ADMIN_CODE, défaut OASIS)'));
