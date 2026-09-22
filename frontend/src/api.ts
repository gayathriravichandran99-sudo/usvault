const API = import.meta.env.VITE_API_URL?.replace(/\/$/, "");
if (!API) throw new Error("VITE_API_URL is required");
async function request(path:string, init?:RequestInit){const r=await fetch(`${API}${path}`,{...init,credentials:"include"});const d=r.status===204?null:await r.json().catch(()=>null);if(!r.ok)throw new Error(d?.error||"Request failed");return d}
export const api={
 requestOtp:(email:string)=>request("/auth/request-otp",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({email})}),
 verifyPair:(body:any)=>request("/auth/verify-pair",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)}),
 logout:()=>request("/auth/logout",{method:"POST"}), vault:()=>request("/vault"),
 deviceChallenge:()=>request("/crypto/device-key/challenge"), registerDevice:(body:any)=>request("/crypto/device-key",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)}),
 saveEnvelope:(deviceKeyId:string,wrappedVaultKey:string,version:number)=>request("/crypto/envelope",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({deviceKeyId,wrappedVaultKey,version})}),
 upload:(blob:Blob,name:string,mime:string,folderId:string|null)=>{const fd=new FormData();fd.append("image",new File([blob],name,{type:"application/octet-stream"}));fd.append("mimeType",mime);if(folderId)fd.append("folderId",folderId);return request("/images",{method:"POST",body:fd})},
 ciphertext:async(id:string)=>{const r=await fetch(`${API}/images/${id}/ciphertext`,{credentials:"include"});if(!r.ok)throw new Error("Unable to fetch encrypted photo");const b=await r.arrayBuffer();return {data:btoa(String.fromCharCode(...new Uint8Array(b)))} }, move:(id:string,folderId:string|null)=>request(`/images/${id}/move`,{method:"PATCH",headers:{"Content-Type":"application/json"},body:JSON.stringify({folderId})}),
 remove:(id:string)=>request(`/images/${id}`,{method:"DELETE"}), createFolder:(name:string,parentId:string|null)=>request("/folders",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({name,parentId})})
};
