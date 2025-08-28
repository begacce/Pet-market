// Backend kodu (Express)
const express = require('express');
const bcrypt = require('bcrypt');
const db = require('./db');
const { v4: uuidv4 } = require('uuid');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
app.use(helmet());
app.use(cors());
app.use(bodyParser.json({ limit: '2mb' }));

const limiter = rateLimit({ windowMs: 60*1000, max: 60 });
app.use(limiter);

const insertUser = db.prepare(`INSERT INTO users (id,name,email,password_hash) VALUES (@id,@name,@email,@password_hash)`);
const getUserByEmail = db.prepare(`SELECT * FROM users WHERE email = ?`);
const insertListing = db.prepare(`INSERT INTO listings (id,user_id,title,description,price,city,image_base64) VALUES (@id,@user_id,@title,@description,@price,@city,@image_base64)`);
const getListings = db.prepare(`SELECT l.*, u.name as seller_name, u.email as seller_email FROM listings l JOIN users u ON l.user_id = u.id ORDER BY created_at DESC`);
const getListingById = db.prepare(`SELECT * FROM listings WHERE id = ?`);

app.post('/api/register', async (req,res)=>{
  try {
    const { name,email,password } = req.body;
    if (!name || !email || !password) return res.status(400).json({error:'Eksik alan'});
    const existing = getUserByEmail.get(email);
    if (existing) return res.status(409).json({error:'E-posta kayıtlı'});
    const password_hash = await bcrypt.hash(password,10);
    const id = uuidv4();
    insertUser.run({id,name,email,password_hash});
    res.json({success:true,id,name,email});
  } catch(e){ res.status(500).json({error:'Sunucu hatası'}); }
});

app.post('/api/login', async (req,res)=>{
  try {
    const { email,password } = req.body;
    const user = getUserByEmail.get(email);
    if (!user) return res.status(401).json({error:'Geçersiz'});
    const ok = await bcrypt.compare(password,user.password_hash);
    if (!ok) return res.status(401).json({error:'Geçersiz'});
    res.json({success:true,id:user.id,name:user.name,email:user.email});
  } catch(e){ res.status(500).json({error:'Sunucu hatası'}); }
});

app.post('/api/listings',(req,res)=>{
  try {
    const { user_id,title,description,price,city,image_base64 } = req.body;
    if (!user_id || !title) return res.status(400).json({error:'Eksik'});
    const id = uuidv4();
    insertListing.run({id,user_id,title,description,price,city,image_base64});
    res.json({success:true,id});
  } catch(e){ res.status(500).json({error:'Sunucu hatası'}); }
});

app.get('/api/listings',(req,res)=>{
  try { res.json({listings:getListings.all()}); }
  catch(e){ res.status(500).json({error:'Sunucu hatası'}); }
});

app.get('/api/listings/:id',(req,res)=>{
  const l = getListingById.get(req.params.id);
  if (!l) return res.status(404).json({error:'Bulunamadı'});
  res.json({listing:l});
});

const PORT = process.env.PORT || 4000;
app.listen(PORT,()=>console.log('Server running on '+PORT));