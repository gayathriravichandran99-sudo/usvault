import "dotenv/config";
import express,{Request,Response,NextFunction} from "express";
import cors from "cors"; import helmet from "helmet"; import cookieParser from "cookie-parser"; import multer from "multer"; import crypto from "node:crypto";
import {PrismaClient} from "@prisma/client"; import {z} from "zod"; import {S3Client,PutObjectCommand,GetObjectCommand,DeleteObjectCommand} from "@aws-sdk/client-s3"; import * as RedisModule from "ioredis"; import {RateLimiterRedis} from "rate-limiter-flexible";
const env=z.object({
  NODE_ENV:z.enum(["development","test","production"]).default("development"),
  PORT:z.coerce.number().default(8080),
  FRONTEND_ORIGIN:z.string().url(),
  DATABASE_URL:z.string().min(1),
  REDIS_URL:z.string().min(1),
  SESSION_SECRET:z.string().min(32),
  STORAGE_PROVIDER:z.enum(["local","s3"]).default("local"),
  LOCAL_STORAGE_DIR:z.string().default("./storage"),
  AWS_REGION:z.string().optional(),
  AWS_S3_BUCKET:z.string().optional(),
  RESEND_API_KEY:z.string().min(1),
  RESEND_FROM_EMAIL:z.string().email(),
  OTP_EXPIRES_MINUTES:z.coerce.number().int().min(5).max(15).default(10),
  MAX_UPLOAD_MB:z.coerce.number().int().min(1).max(100).default(50)
}).superRefine((v,ctx)=>{
  if(v.STORAGE_PROVIDER==="s3"){
    if(!v.AWS_REGION)ctx.addIssue({code:"custom",path:["AWS_REGION"],message:"Required when STORAGE_PROVIDER=s3"});
    if(!v.AWS_S3_BUCKET)ctx.addIssue({code:"custom",path:["AWS_S3_BUCKET"],message:"Required when STORAGE_PROVIDER=s3"});
  }
}).parse(process.env);
import {mkdir,writeFile,readFile,unlink} from "node:fs/promises";
import path from "node:path";
const RedisClient=(RedisModule as any).default ?? RedisModule;
const prisma=new PrismaClient(),redis=new RedisClient(env.REDIS_URL);
const s3=env.STORAGE_PROVIDER==="s3" ? new S3Client({region:env.AWS_REGION}) : null;
const localStorageDir=path.resolve(env.LOCAL_STORAGE_DIR);
const routeId=(value:string|string[]|undefined)=>Array.isArray(value)?value[0]??"":value??"";

const app=express();
app.disable("x-powered-by"); app.set("trust proxy",1);
app.use(helmet({
  contentSecurityPolicy:{directives:{defaultSrc:["'self'"],baseUri:["'self'"],formAction:["'self'"],frameAncestors:["'none'"],objectSrc:["'none'"],scriptSrc:["'self'"],styleSrc:["'self'"],imgSrc:["'self'","blob:","data:"],connectSrc:["'self'",env.FRONTEND_ORIGIN],fontSrc:["'self'","data:"],mediaSrc:["'self'","blob:"]}},
  crossOriginResourcePolicy:{policy:"same-site"},
  referrerPolicy:{policy:"no-referrer"},
  hsts: env.NODE_ENV==="production" ? {maxAge:31536000,includeSubDomains:true,preload:true} : false
})); app.use(cors({origin:env.FRONTEND_ORIGIN,credentials:true,methods:["GET","POST","DELETE","PATCH","OPTIONS"],allowedHeaders:["Content-Type","X-Vault-Key-Version"]})); app.use(express.json({limit:"200kb"})); app.use(cookieParser()); app.use((req,res,next)=>requireSameOrigin(req,res,next));
const otpLimiter=new RateLimiterRedis({storeClient:redis,keyPrefix:"otp",points:5,duration:15*60}); const authLimiter=new RateLimiterRedis({storeClient:redis,keyPrefix:"auth",points:10,duration:15*60}); const verifyEmailLimiter=new RateLimiterRedis({storeClient:redis,keyPrefix:"verify-email",points:8,duration:15*60}); const upload=multer({storage:multer.memoryStorage(),limits:{fileSize:env.MAX_UPLOAD_MB*1024*1024}});
type Session={vaultId:string,userId:string,deviceKeyId:string}; declare global{namespace Express{interface Request{session?:Session}}};
const SESSION_TTL_SECONDS=7*24*60*60;
const sessionCookie="cv_session";
async function readSession(req:Request){
  const token=req.cookies[sessionCookie]; if(!token||typeof token!=="string") return null;
  try { const raw=await redis.get(`session:${token}`); if(!raw) return null; return JSON.parse(raw) as Session; } catch { return null; }
}
async function requireSession(req:Request,res:Response,next:NextFunction){
  const s=await readSession(req); if(!s) return res.status(401).json({error:"Unauthorized"});
  const d=await prisma.deviceKey.findFirst({where:{id:s.deviceKeyId,vaultId:s.vaultId,userId:s.userId,revokedAt:null}});
  if(!d) return res.status(401).json({error:"Device session expired"});
  req.session=s; next();
}
function sameOrigin(req:Request){
  const origin=req.get("origin");
  return !origin || origin===env.FRONTEND_ORIGIN;
}
function requireSameOrigin(req:Request,res:Response,next:NextFunction){
  if(!sameOrigin(req)) return res.status(403).json({error:"Forbidden"});
  next();
}
const email=(e:string)=>e.trim().toLowerCase(), otp=()=>crypto.randomInt(100000,1000000).toString(), hash=(x:string)=>crypto.createHash("sha256").update(x).digest("hex");
async function sendOtp(to:string,code:string){
  const subject="Your UsVault verification code";
  const text=`Your verification code is ${code}. It expires in ${env.OTP_EXPIRES_MINUTES} minutes.`;
  console.log(`[OTP] sending verification code to ${to}`);
  const response=await fetch("https://api.resend.com/emails",{method:"POST",headers:{Authorization:`Bearer ${env.RESEND_API_KEY}`,"Content-Type":"application/json"},body:JSON.stringify({from:env.RESEND_FROM_EMAIL,to:[to],subject,text})});
  if(!response.ok){
    const error=new Error(`Resend rejected email for ${to}: ${response.status}`) as Error & {providerStatus?:number};
    error.providerStatus=response.status;
    throw error;
  }
}
async function putCiphertext(key:string,body:Buffer){
  if(env.STORAGE_PROVIDER==="local"){await mkdir(path.dirname(path.join(localStorageDir,key)),{recursive:true});await writeFile(path.join(localStorageDir,key),body);return}
  if(!s3 || !env.AWS_S3_BUCKET) throw new Error("S3 is not configured");
  await s3.send(new PutObjectCommand({Bucket:env.AWS_S3_BUCKET,Key:key,Body:body,ContentType:"application/octet-stream",ServerSideEncryption:"aws:kms",Metadata:{e2ee:"client"}}));
}
async function getCiphertext(key:string):Promise<Buffer>{
  if(env.STORAGE_PROVIDER==="local") return readFile(path.join(localStorageDir,key));
  if(!s3 || !env.AWS_S3_BUCKET) throw new Error("S3 is not configured");
  const o=await s3.send(new GetObjectCommand({Bucket:env.AWS_S3_BUCKET,Key:key}));
  if(!o.Body) throw new Error("Object missing");
  const chunks:Buffer[]=[];for await(const c of o.Body as any)chunks.push(Buffer.from(c));return Buffer.concat(chunks);
}
async function deleteCiphertext(key:string){
  if(env.STORAGE_PROVIDER==="local"){try{await unlink(path.join(localStorageDir,key))}catch{};return}
  if(!s3 || !env.AWS_S3_BUCKET) throw new Error("S3 is not configured");
  await s3.send(new DeleteObjectCommand({Bucket:env.AWS_S3_BUCKET,Key:key}));
}
async function issueOtp(e:string){const u=await prisma.user.upsert({where:{email:e},update:{},create:{email:e}});const c=otp();await prisma.otp.deleteMany({where:{userId:u.id,purpose:"LOGIN",consumedAt:null}});await prisma.otp.create({data:{userId:u.id,codeHash:hash(c),purpose:"LOGIN",expiresAt:new Date(Date.now()+env.OTP_EXPIRES_MINUTES*60000)}});await sendOtp(e,c)}
async function verifyOtp(e:string,c:string){const u=await prisma.user.findUnique({where:{email:e}});if(!u)return null;const o=await prisma.otp.findFirst({where:{userId:u.id,purpose:"LOGIN",consumedAt:null,expiresAt:{gt:new Date()}},orderBy:{createdAt:"desc"}});if(!o)return null;const a=Buffer.from(hash(c),"hex"),b=Buffer.from(o.codeHash,"hex");if(a.length!==b.length||!crypto.timingSafeEqual(a,b))return null;await prisma.otp.update({where:{id:o.id},data:{consumedAt:new Date()}});return u}
async function findVault(a:string,b:string){return prisma.vault.findFirst({where:{OR:[{memberA:{email:a},memberB:{email:b}},{memberA:{email:b},memberB:{email:a}}]}})}
function safeName(n:string){return n.replace(/[^\w.\-() ]+/g,"_").slice(0,180)||"image"}
app.get("/health",(_,res)=>res.json({ok:true,e2ee:true}));
app.post("/auth/request-otp",async(req,res)=>{
 try{
  const e=email(z.object({email:z.string().email()}).parse(req.body).email);
  await otpLimiter.consume(`email:${e}`);
  await issueOtp(e);
  res.json({ok:true});
 }catch(error:any){
  if(error?.msBeforeNext!==undefined) return res.status(429).json({error:"Too many OTP requests for this email. Try again later."});
  if(error?.name==="ZodError") return res.status(400).json({error:"Enter a valid email address."});
  console.error("OTP delivery failed",error);
  if(error?.providerStatus===403) return res.status(502).json({error:"Resend testing mode only sends to its own account email. Verify a sending domain and use that domain in RESEND_FROM_EMAIL."});
  res.status(502).json({error:"OTP email could not be delivered. Check the email address and try again."});
 }
});
app.post("/auth/verify-pair",async(req,res)=>{try{await authLimiter.consume(`pair:${req.ip}`);const body=z.object({emailA:z.string().email(),emailB:z.string().email(),codeA:z.string().regex(/^\d{6}$/),codeB:z.string().regex(/^\d{6}$/),activeEmail:z.string().email()}).parse(req.body);const a=email(body.emailA),b=email(body.emailB),active=email(body.activeEmail);if(![a,b].includes(active))return res.status(400).json({error:"Active email must be one of the verified partners."});if(a===b)return res.status(400).json({error:"Use two different email addresses."});await Promise.all([verifyEmailLimiter.consume(`email:${a}`),verifyEmailLimiter.consume(`email:${b}`)]);
const [ua,ub]=await Promise.all([verifyOtp(a,body.codeA),verifyOtp(b,body.codeB)]);if(!ua||!ub)return res.status(401).json({error:"One or both verification codes are invalid or expired."});let v=await findVault(a,b);if(!v)v=await prisma.vault.create({data:{memberAId:ua.id,memberBId:ub.id,name:"Our Vault"}});const activeUser=active===a?ua:ub;
// A login creates a fresh browser device. The private key never leaves the browser.
const deviceChallenge=crypto.randomBytes(32).toString("base64url");
await redis.set(`login-device-challenge:${activeUser.id}:${deviceChallenge}`,"1","EX",300);
const token=crypto.randomBytes(32).toString("base64url");
// Device registration happens immediately after login; session is temporarily bound to a login token.
await redis.set(`pending-session:${token}`,JSON.stringify({vaultId:v.id,userId:activeUser.id}),"EX",300);
res.cookie(sessionCookie,token,{httpOnly:true,secure:env.NODE_ENV==="production",sameSite:env.NODE_ENV==="production"?"none":"lax",maxAge:5*60*1000,path:"/"});
res.json({ok:true,vaultId:v.id,userId:activeUser.id,memberAId:v.memberAId,memberBId:v.memberBId});}catch(e){res.status(400).json({error:"Unable to verify pair."})}});
app.post("/auth/logout",async(req,res)=>{const token=req.cookies[sessionCookie];if(token){await redis.del(`session:${token}`,`pending-session:${token}`)}res.clearCookie(sessionCookie,{httpOnly:true,secure:env.NODE_ENV==="production",sameSite:env.NODE_ENV==="production"?"none":"lax",path:"/"});res.status(204).end()});
app.get("/vault",requireSession,async(req,res)=>{const s=req.session!;const v=await prisma.vault.findUnique({where:{id:s.vaultId},include:{folders:true,images:{select:{id:true,folderId:true,originalName:true,mimeType:true,size:true,keyVersion:true,createdAt:true}}}});if(!v)return res.status(404).json({error:"Vault not found"});const devices=await prisma.deviceKey.findMany({where:{vaultId:v.id,revokedAt:null},select:{id:true,userId:true,publicKeyJwk:true,label:true,createdAt:true}});const envelopes=await prisma.vaultKeyEnvelope.findMany({where:{vaultId:v.id},select:{id:true,userId:true,deviceKeyId:true,wrappedVaultKey:true,version:true}}).catch(()=>[] as any[]);res.json({...v,currentUserId:s.userId,devices,envelopes})});
app.post("/crypto/device-key/challenge",async(req,res)=>{
  const token=req.cookies[sessionCookie]; const pending=token?await redis.get(`pending-session:${token}`):null;
  if(!pending) return res.status(401).json({error:"Unauthorized"});
  const p=JSON.parse(pending) as {vaultId:string,userId:string};
  const challenge=crypto.randomBytes(32).toString("base64url");
  await redis.set(`device-challenge:${token}:${challenge}`,JSON.stringify(p),"EX",300);
  res.json({challenge});
});
app.post("/crypto/device-key",async(req,res)=>{
 try{
  const token=req.cookies[sessionCookie]; const pending=token?await redis.get(`pending-session:${token}`):null;
  if(!pending) return res.status(401).json({error:"Unauthorized"});
  const p=JSON.parse(pending) as {vaultId:string,userId:string};
  const body=z.object({publicKeyJwk:z.object({encryption:z.record(z.string(),z.any()),signing:z.record(z.string(),z.any())}),signature:z.string().min(20),challenge:z.string().min(20),label:z.string().max(80).optional()}).parse(req.body);
  const challengeKey=`device-challenge:${token}:${body.challenge}`;
  const valid=await redis.get(challengeKey); if(!valid) return res.status(401).json({error:"Device proof failed"});
  await redis.del(challengeKey);
  const pub=await crypto.webcrypto.subtle.importKey("jwk",body.publicKeyJwk.signing,{name:"ECDSA",namedCurve:"P-256"},false,["verify"]);
  const ok=await crypto.webcrypto.subtle.verify({name:"ECDSA",hash:"SHA-256"},pub,Buffer.from(body.signature,"base64"),new TextEncoder().encode(body.challenge));
  if(!ok)return res.status(401).json({error:"Device proof failed"});
  const count=await prisma.deviceKey.count({where:{vaultId:p.vaultId,userId:p.userId,revokedAt:null}});
  if(count>=10)return res.status(429).json({error:"Device limit reached"});
  const d=await prisma.deviceKey.create({data:{vaultId:p.vaultId,userId:p.userId,publicKeyJwk:body.publicKeyJwk as any,signingPublicKeyJwk:body.publicKeyJwk.signing as any,label:body.label||"Browser"}});
  await redis.del(`pending-session:${token}`);
  const sessionToken=crypto.randomBytes(32).toString("base64url");
  await redis.set(`session:${sessionToken}`,JSON.stringify({vaultId:p.vaultId,userId:p.userId,deviceKeyId:d.id}),"EX",SESSION_TTL_SECONDS);
  res.cookie(sessionCookie,sessionToken,{httpOnly:true,secure:env.NODE_ENV==="production",sameSite:env.NODE_ENV==="production"?"none":"lax",maxAge:SESSION_TTL_SECONDS*1000,path:"/"});
  res.json({id:d.id});
 }catch{res.status(400).json({error:"Invalid device key"})}
});
app.post("/crypto/envelope",requireSession,async(req,res)=>{try{const s=req.session!,body=z.object({deviceKeyId:z.string(),wrappedVaultKey:z.string().min(20),version:z.number().int().positive()}).parse(req.body);const d=await prisma.deviceKey.findFirst({where:{id:body.deviceKeyId,vaultId:s.vaultId}});if(!d)return res.status(404).json({error:"Device not found"});const v=await prisma.vault.findUnique({where:{id:s.vaultId}});if(!v||![v.memberAId,v.memberBId].includes(s.userId))return res.status(403).json({error:"Forbidden"});const e=await prisma.vaultKeyEnvelope.upsert({where:{vaultId_deviceKeyId_version:{vaultId:s.vaultId,deviceKeyId:d.id,version:body.version}},create:{vaultId:s.vaultId,userId:d.userId,deviceKeyId:d.id,wrappedVaultKey:body.wrappedVaultKey,version:body.version},update:{wrappedVaultKey:body.wrappedVaultKey}});res.json({id:e.id})}catch{res.status(400).json({error:"Invalid key envelope"})}});
app.delete("/crypto/device-key/:id",requireSession,async(req,res)=>{
 const s=req.session!;
 const id=routeId(req.params.id);
 const d=await prisma.deviceKey.findFirst({where:{id,vaultId:s.vaultId,userId:s.userId,revokedAt:null}});
 if(!d)return res.status(404).end();
 await prisma.deviceKey.update({where:{id:d.id},data:{revokedAt:new Date()}});
 res.status(204).end();
});
app.post("/images",requireSession,upload.single("image"),async(req,res)=>{try{const s=req.session!;if(!req.file)return res.status(400).json({error:"Image required"});const declaredMime=z.string().refine(x=>["image/jpeg","image/png","image/webp","image/gif","image/heic","image/heif","image/avif"].includes(x),"Unsupported image format").parse(req.body.mimeType);const folderId=req.body.folderId||null;if(folderId){const f=await prisma.folder.findFirst({where:{id:folderId,vaultId:s.vaultId}});if(!f)return res.status(400).json({error:"Invalid folder"})}const id=crypto.randomUUID();const key=`vaults/${s.vaultId}/objects/${id}`;await putCiphertext(key,req.file.buffer);const image=await prisma.image.create({data:{id,vaultId:s.vaultId,folderId,originalName:safeName(req.file.originalname),mimeType:declaredMime,size:req.file.size,storageKey:key,keyVersion:1}});res.json({id:image.id,originalName:image.originalName,mimeType:image.mimeType,size:image.size,keyVersion:image.keyVersion,createdAt:image.createdAt})}catch(e){console.error(e);res.status(500).json({error:"Upload failed"})}});
app.get("/images/:id/ciphertext",requireSession,async(req,res)=>{try{const s=req.session!;const id=routeId(req.params.id);const im=await prisma.image.findFirst({where:{id,vaultId:s.vaultId}});if(!im)return res.status(404).end();const body=await getCiphertext(im.storageKey);res.setHeader("Cache-Control","private, no-store");res.setHeader("Content-Type","application/octet-stream");res.end(body)}catch{res.status(404).end()}});
app.delete("/images/:id",requireSession,async(req,res)=>{const s=req.session!;const id=routeId(req.params.id);const im=await prisma.image.findFirst({where:{id,vaultId:s.vaultId}});if(!im)return res.status(404).end();await deleteCiphertext(im.storageKey);await prisma.image.delete({where:{id:im.id}});res.status(204).end()});
app.patch("/images/:id/move",requireSession,async(req,res)=>{const s=req.session!;const id=routeId(req.params.id);const body=z.object({folderId:z.string().nullable()}).parse(req.body);if(body.folderId){const f=await prisma.folder.findFirst({where:{id:body.folderId,vaultId:s.vaultId}});if(!f)return res.status(400).json({error:"Invalid folder"})}const im=await prisma.image.findFirst({where:{id,vaultId:s.vaultId}});if(!im)return res.status(404).end();await prisma.image.update({where:{id:im.id},data:{folderId:body.folderId}});res.status(204).end()});
app.post("/folders",requireSession,async(req,res)=>{const s=req.session!,body=z.object({name:z.string().trim().min(1).max(80),parentId:z.string().nullable()}).parse(req.body);if(body.parentId){const p=await prisma.folder.findFirst({where:{id:body.parentId,vaultId:s.vaultId}});if(!p)return res.status(400).json({error:"Invalid parent"})}const f=await prisma.folder.create({data:{vaultId:s.vaultId,name:body.name,parentId:body.parentId}});res.json(f)});
const port=env.PORT;
const server=app.listen(port,()=>console.log(`UsVault API listening on ${port}`));
async function shutdown(){server.close();await prisma.$disconnect();await redis.quit();}
process.on("SIGTERM",shutdown); process.on("SIGINT",shutdown);
