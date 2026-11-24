// Wanderer Payment independent API, Cloudflare Worker + D1.
const DEFAULT = {
  shopName: 'Wanderer Shop', eyebrow: '✦ PAYMENT CENTER ✦',
  title: 'ช่องทางชำระเงิน', subtitle: 'ชำระเงินสะดวก ปลอดภัย ตรวจสอบชื่อบัญชีก่อนโอนทุกครั้ง',
  bank: 'ธนาคารตัวอย่าง', bankName: 'ตัวอย่างบัญชี (ยังไม่ใช่บัญชีรับเงินจริง)',
  bankNumber: '000-0-00000-0', walletNumber: '', promptPayNumber: '', logoSize: 150,
  warningText: '✩ โปรดตรวจสอบชื่อและเลขบัญชีก่อนโอน\n✩ หลังโอนกรุณาส่งสลิปผ่านช่องทางติดต่อร้าน',
  slipNote: '',
  accent: '#9c82e9', secondary: '#88c9f6', backgroundColor: '#e7e0ff',
  backgroundMode: 'gradient',
  floatingText: '✦ thank you for supporting our little shop ✦',
  floatX: 50, floatY: 18, floatSize: 18,
  floatAnimate: true, floatImage: false,
  links: [
    {label:'เว็บสินค้า', icon:'🛍️', url:'https://YOUR-MAIN-SHOP.example'},
    {label:'รีวิว', icon:'☆', url:''},
    {label:'ติดต่อ', icon:'💬', url:''},
    {label:'ตัวอย่างเว็บ', icon:'🖥️', url:''}
  ]
};
const encoder = new TextEncoder();
const responseJson=(body,status=200,headers={})=>new Response(JSON.stringify(body),{status,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store',...headers}});
function cors(origin,env){const allow=(env.ALLOWED_ORIGIN||'').split(',').map(x=>x.trim()).filter(Boolean);return origin&&allow.includes(origin)?{'Access-Control-Allow-Origin':origin,'Vary':'Origin'}:{}};
const security={'X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer'};
const equal=(a,b)=>{const x=encoder.encode(a),y=encoder.encode(b);let mismatch=x.length^y.length;for(let i=0;i<Math.max(x.length,y.length);i++)mismatch|=(x[i]||0)^(y[i]||0);return mismatch===0;};
async function sha(s){const bytes=new Uint8Array(await crypto.subtle.digest('SHA-256',encoder.encode(s)));return [...bytes].map(x=>x.toString(16).padStart(2,'0')).join('');}
async function hmac(secret,data){const key=await crypto.subtle.importKey('raw',encoder.encode(secret),{name:'HMAC',hash:'SHA-256'},false,['sign']);const sig=new Uint8Array(await crypto.subtle.sign('HMAC',key,encoder.encode(data)));return [...sig].map(x=>x.toString(16).padStart(2,'0')).join('');}
async function isAuthorized(request,env){const token=(request.headers.get('Authorization')||'').replace(/^Bearer /,'');const match=/^(\d+)\.([a-f0-9]{64})$/.exec(token);if(!match)return false;const expires=Number(match[1]);if(!Number.isSafeInteger(expires)||expires<Date.now()||expires>Date.now()+12*3600*1000)return false;return equal(match[2],await hmac(env.SESSION_SECRET||'',match[1]));}
function normalizeURL(url){if(!url)return '';try{let u=new URL(url);return ['https:','http:'].includes(u.protocol)?u.href:''}catch{return ''}}
const clamp=(x,min,max,def)=>Number.isFinite(Number(x))?Math.max(min,Math.min(max,Number(x))):def;
const trim=(x,max)=>String(x??'').slice(0,max);
function sanitize(input){if(!input||typeof input!=='object')throw Error('ข้อมูลไม่ถูกต้อง');
  const o={
    shopName:trim(input.shopName,80),eyebrow:trim(input.eyebrow,80),title:trim(input.title,100),subtitle:trim(input.subtitle,240),
    bank:trim(input.bank,90),bankName:trim(input.bankName,120),bankNumber:trim(input.bankNumber,60),walletNumber:trim(input.walletNumber,30),promptPayNumber:trim(input.promptPayNumber,30),logoSize:clamp(input.logoSize,70,240,150),warningText:trim(input.warningText??input.note,900),slipNote:trim(input.slipNote,600),
    accent:/^#[0-9a-f]{6}$/i.test(input.accent)?input.accent:DEFAULT.accent,
    secondary:/^#[0-9a-f]{6}$/i.test(input.secondary)?input.secondary:DEFAULT.secondary,
    backgroundColor:/^#[0-9a-f]{6}$/i.test(input.backgroundColor)?input.backgroundColor:DEFAULT.backgroundColor,
    backgroundMode:['gradient','color','image'].includes(input.backgroundMode)?input.backgroundMode:'gradient',
    floatingText:trim(input.floatingText,180),floatX:clamp(input.floatX,5,95,50),floatY:clamp(input.floatY,5,90,18),floatSize:clamp(input.floatSize,11,42,18),
    floatAnimate:!!input.floatAnimate,floatImage:!!input.floatImage,
    links:(Array.isArray(input.links)?input.links:[]).slice(0,5).map(l=>({label:trim(l.label,22),icon:trim(l.icon,5),url:normalizeURL(l.url)}))
  };
  if(!o.shopName||!o.bankName||!o.bankNumber)throw Error('กรุณากรอกชื่อร้าน ชื่อบัญชี และเลขบัญชี');return o;
}
async function getSite(db){const r=await db.prepare('SELECT data,revision FROM site_config WHERE id=1').first();if(!r)return {config:DEFAULT,revision:0};const saved=JSON.parse(r.data);return {config:{...DEFAULT,...saved,warningText:saved.warningText??saved.note??DEFAULT.warningText,slipNote:saved.slipNote??DEFAULT.slipNote},revision:r.revision};}
async function getSlots(db){const rows=await db.prepare('SELECT slot FROM image_assets').all();return Object.fromEntries((rows.results||[]).map(r=>[r.slot,true]));}
function decodeBase64(str){const decoded=atob(str);return Uint8Array.from(decoded,c=>c.charCodeAt(0));}
function encodeBase64(buf){const bytes=new Uint8Array(buf);let value='';for(let i=0;i<bytes.length;i+=8192)value+=String.fromCharCode(...bytes.subarray(i,i+8192));return btoa(value);}
async function bumpRevision(db){await db.prepare('UPDATE site_config SET revision=revision+1, updated_at=CURRENT_TIMESTAMP WHERE id=1').run();}
export default {async fetch(request,env){
  const origin=request.headers.get('Origin');const headers={...cors(origin,env),...security};
  const u=new URL(request.url);const p=u.pathname.replace(/\/$/,'')||'/';
  const send=(body,status=200)=>responseJson(body,status,headers);
  if(request.method==='OPTIONS')return new Response(null,{status:204,headers:{...headers,'Access-Control-Allow-Methods':'GET,POST,PUT,DELETE,OPTIONS','Access-Control-Allow-Headers':'Authorization, Content-Type','Access-Control-Max-Age':'600'}});
  if(origin&&!headers['Access-Control-Allow-Origin'])return send({error:'Origin not allowed'},403);
  try{
    if(p==='/health')return send({ok:true,service:'wanderer-payment',database:'D1'});
    if(p==='/api/public'&&request.method==='GET'){
      const {config,revision}=await getSite(env.DB);
      return send({ok:true,config,revision,images:await getSlots(env.DB)});
    }
    if(p.startsWith('/api/image/')&&request.method==='GET'){
      const slot=p.split('/')[3];if(!['logo','qr','background','floating'].includes(slot))return send({error:'Invalid image'},404);
      const img=await env.DB.prepare('SELECT mime,base64_data FROM image_assets WHERE slot=?').bind(slot).first();
      if(!img)return send({error:'Image not found'},404);
      return new Response(decodeBase64(img.base64_data),{headers:{...headers,'content-type':img.mime,'cache-control':'public, max-age=60'}});
    }
    if(p==='/api/login'&&request.method==='POST'){
      if(!env.ADMIN_PASSWORD||!env.SESSION_SECRET)return send({error:'Configure Worker secrets first'},503);
      const ip=request.headers.get('CF-Connecting-IP')||'unknown';const ipKey=await sha(ip+'|'+env.SESSION_SECRET);
      const now=Math.floor(Date.now()/1000),old=await env.DB.prepare('SELECT hits,window_start FROM login_attempts WHERE ip_key=?').bind(ipKey).first();
      if(old&&old.hits>=6&&now-old.window_start<900)return send({error:'ลองเข้าสู่ระบบใหม่หลัง 15 นาที'},429);
      const v=await request.json();const match=equal(await sha(String(v.password??'')),await sha(env.ADMIN_PASSWORD));
      if(!match){await env.DB.prepare('INSERT INTO login_attempts(ip_key,hits,window_start) VALUES(?,?,?) ON CONFLICT(ip_key) DO UPDATE SET hits=?,window_start=?').bind(ipKey,old&&now-old.window_start<900?old.hits+1:1,old&&now-old.window_start<900?old.window_start:now,old&&now-old.window_start<900?old.hits+1:1,old&&now-old.window_start<900?old.window_start:now).run();return send({error:'รหัสผ่านไม่ถูกต้อง'},401)}
      await env.DB.prepare('DELETE FROM login_attempts WHERE ip_key=?').bind(ipKey).run();
      const expiry=String(Date.now()+4*3600*1000);return send({token:expiry+'.'+await hmac(env.SESSION_SECRET,expiry),expiresAt:Number(expiry)});
    }
    if(['/api/config','/api/upload'].includes(p)||p.startsWith('/api/upload/')){
      if(!await isAuthorized(request,env))return send({error:'กรุณาเข้าสู่ระบบแอดมิน'},401);
      if(p==='/api/config'&&request.method==='PUT'){
        const body=await request.text();if(body.length>30000)return send({error:'ข้อมูลใหญ่เกินไป'},413);
        let config;try{config=sanitize(JSON.parse(body))}catch(e){return send({error:e.message},400)}
        await env.DB.prepare('INSERT INTO site_config(id,data,revision) VALUES(1,?,1) ON CONFLICT(id) DO UPDATE SET data=excluded.data,revision=revision+1,updated_at=CURRENT_TIMESTAMP').bind(JSON.stringify(config)).run();
        const {revision}=await getSite(env.DB);return send({ok:true,revision,config});
      }
      if(p==='/api/upload'&&request.method==='POST'){
        const slot=u.searchParams.get('slot');if(!['logo','qr','background','floating'].includes(slot))return send({error:'ตำแหน่งรูปไม่ถูกต้อง'},400);
        const mime=request.headers.get('content-type')||'';if(!['image/png','image/jpeg','image/webp'].includes(mime))return send({error:'รองรับเฉพาะ PNG JPG WebP'},415);
        const bytes=await request.arrayBuffer();if(!bytes.byteLength||bytes.byteLength>500000)return send({error:'ไฟล์ต้องไม่เกิน 500 KB'},413);
        await env.DB.prepare('INSERT INTO image_assets(slot,mime,base64_data) VALUES(?,?,?) ON CONFLICT(slot) DO UPDATE SET mime=excluded.mime,base64_data=excluded.base64_data,updated_at=CURRENT_TIMESTAMP').bind(slot,mime,encodeBase64(bytes)).run();
        await env.DB.prepare('INSERT OR IGNORE INTO site_config(id,data,revision) VALUES(1,?,1)').bind(JSON.stringify(DEFAULT)).run();
        await bumpRevision(env.DB);return send({ok:true});
      }
      if(p.startsWith('/api/upload/')&&request.method==='DELETE'){
        const slot=p.split('/')[3];if(!['logo','qr','background','floating'].includes(slot))return send({error:'ตำแหน่งรูปไม่ถูกต้อง'},400);
        await env.DB.prepare('DELETE FROM image_assets WHERE slot=?').bind(slot).run();await bumpRevision(env.DB);return send({ok:true});
      }
      return send({error:'Method not allowed'},405);
    }
    return send({error:'Not found'},404);
  }catch(e){console.error(e);return send({error:'เกิดข้อผิดพลาดของเซิร์ฟเวอร์'},500)}
}};
