import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import multer from "multer";
import path from "path";
import { fileURLToPath } from "url";
import db from "./db.js";

const app=express(), port=5001, secret=process.env.JWT_SECRET||"local-secret";
const folder=path.dirname(fileURLToPath(import.meta.url));
app.use(cors()); app.use(express.json()); app.use("/uploads",express.static(path.join(folder,"uploads")));
const storage=multer.diskStorage({destination:path.join(folder,"uploads"),filename:(req,file,done)=>done(null,Date.now()+path.extname(file.originalname))});
const upload=multer({storage});
function auth(req,res,next){try{req.user=jwt.verify(req.headers.authorization?.split(" ")[1],secret);next()}catch{res.status(401).json({message:"Please login"})}}
function photoView(p){return {_id:p.id,fileName:p.file_name,title:p.title,description:p.description,dateTime:p.date_time,userId:{_id:p.user_id,firstName:p.user_name||p.first_name,lastName:p.last_name}}}

app.post("/api/auth/register",async(req,res)=>{try{const {firstName,lastName,email,password}=req.body;if(!firstName||!lastName||!email||!password)return res.status(400).json({message:"All fields are required"});const [result]=await db.execute("INSERT INTO users (first_name,last_name,email,password) VALUES (?,?,?,?)",[firstName,lastName,email,await bcrypt.hash(password,10)]);res.json({id:result.insertId,token:jwt.sign({id:result.insertId,firstName},secret),firstName})}catch{res.status(400).json({message:"Email already exists"})}});
app.post("/api/auth/login",async(req,res)=>{const [rows]=await db.execute("SELECT * FROM users WHERE email=?",[req.body.email]);const user=rows[0];if(!user||!(await bcrypt.compare(req.body.password,user.password)))return res.status(401).json({message:"Incorrect login"});res.json({id:user.id,token:jwt.sign({id:user.id,firstName:user.first_name},secret),firstName:user.first_name})});
app.get("/api/photos",async(req,res)=>{const [rows]=await db.execute("SELECT photos.*,users.first_name AS user_name FROM photos JOIN users ON users.id=photos.user_id ORDER BY photos.date_time DESC");res.json(rows.map(photoView))});
app.get("/api/photos/:id",async(req,res)=>{const [photos]=await db.execute("SELECT photos.*,users.first_name,users.last_name FROM photos JOIN users ON users.id=photos.user_id WHERE photos.id=?",[req.params.id]);const [comments]=await db.execute("SELECT comments.*,users.first_name FROM comments JOIN users ON users.id=comments.user_id WHERE photo_id=? ORDER BY comments.date_time",[req.params.id]);if(!photos[0])return res.status(404).json({message:"Photo not found"});const p=photos[0];res.json({photo:photoView(p),comments:comments.map(c=>({_id:c.id,comment:c.comment,dateTime:c.date_time,userId:{firstName:c.first_name}}))})});
app.post("/api/photos",auth,upload.single("image"),async(req,res)=>{const [result]=await db.execute("INSERT INTO photos (user_id,file_name,title,description) VALUES (?,?,?,?)",[req.user.id,req.file.filename,req.body.title,req.body.description]);res.json({id:result.insertId})});
app.post("/api/photos/:id/comments",auth,async(req,res)=>{const [result]=await db.execute("INSERT INTO comments (photo_id,user_id,comment) VALUES (?,?,?)",[req.params.id,req.user.id,req.body.comment]);res.json({id:result.insertId})});
app.delete("/api/photos/:id",auth,async(req,res)=>{const [result]=await db.execute("DELETE FROM photos WHERE id=? AND user_id=?",[req.params.id,req.user.id]);if(!result.affectedRows)return res.status(403).json({message:"Not your photo"});res.json({ok:true})});
db.query("SELECT 1").then(()=>app.listen(port,()=>console.log(`Server on ${port}`))).catch(console.error);
