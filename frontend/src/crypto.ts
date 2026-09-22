const DB="couple-vault-keys", STORE="keys";
function db(){return new Promise<IDBDatabase>((ok,no)=>{const r=indexedDB.open(DB,1);r.onupgradeneeded=()=>r.result.createObjectStore(STORE);r.onsuccess=()=>ok(r.result);r.onerror=()=>no(r.error)})}
async function put(id:string,v:any){const d=await db();return new Promise<void>((ok,no)=>{const t=d.transaction(STORE,"readwrite");t.objectStore(STORE).put(v,id);t.oncomplete=()=>ok();t.onerror=()=>no(t.error)})}
async function get<T=any>(id:string){const d=await db();return new Promise<T|null>((ok,no)=>{const r=d.transaction(STORE).objectStore(STORE).get(id);r.onsuccess=()=>ok(r.result??null);r.onerror=()=>no(r.error)})}
const b64=(a:ArrayBuffer)=>btoa(String.fromCharCode(...new Uint8Array(a))); const unb64=(s:string)=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
export async function createDevice(){const enc=await crypto.subtle.generateKey({name:"RSA-OAEP",modulusLength:3072,publicExponent:new Uint8Array([1,0,1]),hash:"SHA-256"},false,["encrypt","decrypt"]);const sign=await crypto.subtle.generateKey({name:"ECDSA",namedCurve:"P-256"},false,["sign","verify"]);return {enc,sign}}
export async function saveDevice(id:string,p:any){await put("enc:"+id,p.enc.privateKey);await put("sign:"+id,p.sign.privateKey)}
export async function privateKey(id:string){const enc=await get<CryptoKey>("enc:"+id);const sign=await get<CryptoKey>("sign:"+id);return enc&&sign?{enc,sign}:null}
export async function exportPublic(p:any){return {encryption:await crypto.subtle.exportKey("jwk",p.enc.publicKey),signing:await crypto.subtle.exportKey("jwk",p.sign.publicKey)}}
export async function signChallenge(k:CryptoKey,challenge:string){return b64(await crypto.subtle.sign({name:"ECDSA",hash:"SHA-256"},k,new TextEncoder().encode(challenge)))}
export async function saveVaultKey(vaultId:string,key:CryptoKey){await put("vault-key:"+vaultId,key)}
export async function vaultKey(vaultId:string){return get<CryptoKey>("vault-key:"+vaultId)}
export async function clearVaultKey(vaultId:string){const d=await db();return new Promise<void>((ok,no)=>{const t=d.transaction(STORE,"readwrite");t.objectStore(STORE).delete("vault-key:"+vaultId);t.oncomplete=()=>ok();t.onerror=()=>no(t.error)})}
export async function makeVaultKey(){return crypto.subtle.generateKey({name:"AES-GCM",length:256},true,["encrypt","decrypt"])}
export async function wrapVaultKey(vaultKey:CryptoKey,publicJwk:any){const pub=await crypto.subtle.importKey("jwk",publicJwk.encryption,{name:"RSA-OAEP",hash:"SHA-256"},false,["encrypt"]);const raw=await crypto.subtle.exportKey("raw",vaultKey);return b64(await crypto.subtle.encrypt({name:"RSA-OAEP"},pub,raw))}
export async function unwrapVaultKey(ciphertext:string,priv:CryptoKey){const raw=await crypto.subtle.decrypt({name:"RSA-OAEP"},priv,unb64(ciphertext));return crypto.subtle.importKey("raw",raw,{name:"AES-GCM"},false,["encrypt","decrypt"])}
export async function encryptFile(file:File,key:CryptoKey){const iv=crypto.getRandomValues(new Uint8Array(12));const ct=await crypto.subtle.encrypt({name:"AES-GCM",iv},key,await file.arrayBuffer());const out=new Uint8Array(12+ct.byteLength);out.set(iv);out.set(new Uint8Array(ct),12);return new Blob([out],{type:"application/octet-stream"})}
export async function decryptBlob(blob:Blob,key:CryptoKey,mime:string){const x=new Uint8Array(await blob.arrayBuffer());const p=await crypto.subtle.decrypt({name:"AES-GCM",iv:x.slice(0,12)},key,x.slice(12));return new Blob([p],{type:mime})}
