import {useEffect,useRef,useState} from "react";
import {motion} from "framer-motion";
import {Heart,Upload,FolderPlus,Download,Trash2,LogOut,Lock,ShieldCheck,RefreshCw} from "lucide-react";
import {api} from "./api"; import * as C from "./crypto";

type Img={id:string;folderId:string|null;originalName:string;mimeType:string;size:number;keyVersion:number;createdAt:string}; type Folder={id:string;parentId:string|null;name:string};
const DEVICE_ID_KEY="cv-device-id"; const getDeviceId=()=>localStorage.getItem(DEVICE_ID_KEY)||""; const setDeviceId=(x:string)=>localStorage.setItem(DEVICE_ID_KEY,x);

export default function App(){
 const [vault,setVault]=useState<any>(null),[a,setA]=useState(""),[b,setB]=useState(""),[ca,setCa]=useState(""),[cb,setCb]=useState(""),[active,setActive]=useState<"a"|"b">("a"),[step,setStep]=useState<"emails"|"codes">("emails"),[error,setError]=useState(""),[busy,setBusy]=useState(false),[keyReady,setKeyReady]=useState(false),[folder,setFolder]=useState<string|null>(null),[preview,setPreview]=useState<string|null>(null),[previewUrl,setPreviewUrl]=useState<string|null>(null); const privateRef=useRef<CryptoKey|null>(null); const vaultKeyRef=useRef<CryptoKey|null>(null);
 async function bootstrap(v:any){
   let did=getDeviceId();
   let priv=did?await C.privateKey(did):null;
   // A successful OTP login may be a new server session even on a browser that already has keys.
   // Register this browser only when the server session has not yet been bound to a device.
   if(!priv){
     const kp=await C.createDevice(); const pub=await C.exportPublic(kp);
     const ch=await api.deviceChallenge();
     const sig=await C.signChallenge(kp.sign.privateKey,ch.challenge);
     const r=await api.registerDevice({publicKeyJwk:pub,signature:sig,challenge:ch.challenge,label:"Browser"});
     did=r.id; setDeviceId(did); await C.saveDevice(did,kp); priv=await C.privateKey(did);
   }
   if(!priv) throw new Error("Device key unavailable");
   privateRef.current=priv.enc;
   let vk=await C.vaultKey(v.vaultId);
   const mine=v.envelopes?.find((e:any)=>e.deviceKeyId===did && e.version===1);
   if(!vk && mine){
     vk=await C.unwrapVaultKey(mine.wrappedVaultKey,priv.enc); await C.saveVaultKey(v.vaultId,vk);
   }
   if(!vk && (!v.envelopes?.length)){
     vk=await C.makeVaultKey(); await C.saveVaultKey(v.vaultId,vk);
     const me=v.devices?.find((d:any)=>d.id===did);
     if(me) await api.saveEnvelope(did,await C.wrapVaultKey(vk,me.publicKeyJwk),1);
   }
   if(vk){
     vaultKeyRef.current=vk; setKeyReady(true);
     for(const d of v.devices||[]){
       if(d.id!==did){
         const exists=v.envelopes?.some((e:any)=>e.deviceKeyId===d.id&&e.version===1);
         if(!exists) await api.saveEnvelope(d.id,await C.wrapVaultKey(vk,d.publicKeyJwk),1);
       }
     }
   }
   setVault(v);
 }
 async function load(){try{const v=await api.vault();await bootstrap(v)}catch{}}
 useEffect(()=>{load()},[]);
 useEffect(()=>{if(vault&&!keyReady){const t=setInterval(load,3000);return()=>clearInterval(t)}},[vault,keyReady]);
 async function requestCodes(){
  setError("");
  const first=a.trim().toLowerCase();
  const second=b.trim().toLowerCase();
  if(!first || !second){setError("Enter both partner email addresses.");return;}
  const validEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if(!validEmail.test(first) || !validEmail.test(second)){setError("Please enter valid email addresses for both partners.");return;}
  if(first===second){setError("Use two different email addresses.");return;}
  setBusy(true);
  try{
    await Promise.all([api.requestOtp(first), api.requestOtp(second)]);
    setA(first); setB(second); setStep("codes");
  }catch(e:any){setError(e.message || "Unable to send OTP emails.")} finally {setBusy(false)}
 }
 async function login(){setError("");setBusy(true);try{await api.verifyPair({emailA:a,emailB:b,codeA:ca,codeB:cb,activeEmail:active==="a"?a:b});await load()}catch(e:any){setError(e.message)}finally{setBusy(false)}}
 async function uploadFiles(fs:FileList|null){if(!fs||!vaultKeyRef.current)return;setBusy(true);try{for(const f of Array.from(fs)){const blob=await C.encryptFile(f,vaultKeyRef.current);await api.upload(blob,f.name,f.type,folder)}}catch(e:any){setError(e.message)}finally{setBusy(false);await load()}}
 async function newFolder(){const n=prompt("Folder name");if(n){await api.createFolder(n,folder);await load()}}
 async function remove(id:string){if(confirm("Delete this encrypted photo permanently?")){await api.remove(id);await load()}}
 async function previewImage(id:string){if(!vaultKeyRef.current)return;const im:Img=vault.images.find((x:Img)=>x.id===id);if(!im)return;try{const c=await api.ciphertext(id);const blob=new Blob([Uint8Array.from(atob(c.data),x=>x.charCodeAt(0))],{type:"application/octet-stream"});const plain=await C.decryptBlob(blob,vaultKeyRef.current,im.mimeType);if(previewUrl)URL.revokeObjectURL(previewUrl);setPreviewUrl(URL.createObjectURL(plain));setPreview(id)}catch{setError("This photo could not be decrypted. Your device key may be missing.")}}
 async function download(id:string){if(!vaultKeyRef.current)return;const im:Img=vault.images.find((x:Img)=>x.id===id);const c=await api.ciphertext(id);const raw=Uint8Array.from(atob(c.data),x=>x.charCodeAt(0));const plain=await C.decryptBlob(new Blob([raw]),vaultKeyRef.current,im.mimeType);const u=URL.createObjectURL(plain);const a=document.createElement("a");a.href=u;a.download=im.originalName;a.click();setTimeout(()=>URL.revokeObjectURL(u),1000)}
 if(!vault)return <main className="auth"><motion.div className="card" initial={{opacity:0,y:20}} animate={{opacity:1,y:0}}><div className="brand"><Heart fill="currentColor"/><span>usvault</span></div><div className="eyebrow"><ShieldCheck size={14}/> zero-knowledge private vault</div><h1>Not even we can see your memories.</h1><p className="muted">Photos are encrypted in your browser before they leave your device. The server stores ciphertext only.</p>{step==="emails"?<div className="stack"><input value={a} onChange={e=>setA(e.target.value)} placeholder="Partner 1 email" type="email"/><input value={b} onChange={e=>setB(e.target.value)} placeholder="Partner 2 email" type="email"/><button disabled={busy} onClick={requestCodes}>{busy?"Sending…":"Send both codes"}</button></div>:<div className="stack"><div className="seg"><button className={active==="a"?"selected":""} onClick={()=>setActive("a")}>I’m partner 1</button><button className={active==="b"?"selected":""} onClick={()=>setActive("b")}>I’m partner 2</button></div><input value={ca} onChange={e=>setCa(e.target.value)} placeholder="Partner 1 • 6 digit code" inputMode="numeric"/><input value={cb} onChange={e=>setCb(e.target.value)} placeholder="Partner 2 • 6 digit code" inputMode="numeric"/><button disabled={busy} onClick={login}>{busy?"Opening…":"Open our vault"}</button><button className="ghost" onClick={()=>setStep("emails")}>Change emails</button></div>}{error&&<div className="error">{error}</div>}</motion.div></main>;
 const folders:Folder[]=vault.folders; const images:Img[]=vault.images.filter((x:Img)=>x.folderId===folder); return <main className="app"><header><div className="brand"><Heart fill="currentColor"/><span>usvault</span></div><div className="secure"><Lock size={14}/> E2EE</div><button className="icon" onClick={async()=>{await api.logout();if(vault?.vaultId)await C.clearVaultKey(vault.vaultId);vaultKeyRef.current=null;setVault(null);setKeyReady(false)}}><LogOut size={18}/></button></header><section className="hero"><div><div className="eyebrow"><Lock size={14}/> end-to-end encrypted</div><h2>{vault.name}</h2><p className="muted">Your browser encrypts every photo before upload. Only paired devices can decrypt it.</p></div><div className="actions"><label className="button"><Upload size={17}/> {busy?"Working…":"Upload"}<input hidden type="file" accept="image/jpeg,image/png,image/webp,image/gif,image/heic,image/heif,image/avif" multiple onChange={e=>uploadFiles(e.target.files)}/></label><button onClick={newFolder} className="ghost"><FolderPlus size={17}/> New folder</button><button className="icon" onClick={load}><RefreshCw size={17}/></button></div></section><div className="crumb"><button onClick={()=>setFolder(null)}>All memories</button>{folder&&<> / {folders.find(f=>f.id===folder)?.name}</>}</div><div className="folders">{folders.filter(f=>f.parentId===folder).map(f=><button className="folder" key={f.id} onClick={()=>setFolder(f.id)}>📁 {f.name}</button>)}</div><section className="grid">{images.map(img=><motion.article layout key={img.id} className="tile"><div className="lockedThumb" onClick={()=>previewImage(img.id)}><Lock size={22}/><span>Encrypted</span></div><div className="tilebar"><span>{img.originalName}</span><div><button onClick={()=>download(img.id)} title="Decrypt and download"><Download size={16}/></button><button onClick={()=>remove(img.id)}><Trash2 size={16}/></button></div></div></motion.article>)}</section>{!images.length&&<div className="empty"><Heart size={28}/><h3>Your story starts here.</h3><p>Add your first encrypted memory.</p></div>}{preview&&<div className="modal" onClick={()=>{setPreview(null);if(previewUrl)URL.revokeObjectURL(previewUrl);setPreviewUrl(null)}}>{previewUrl?<img src={previewUrl} onClick={e=>e.stopPropagation()}/>:<span>Decrypting…</span>}</div>}</main>
}
