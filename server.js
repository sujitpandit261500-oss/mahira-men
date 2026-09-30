const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const db = new Database(path.join(__dirname, "mahira.db"));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || "mahira-men-change-this-secret",
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 8, sameSite: "lax" }
}));

db.pragma("foreign_keys = ON");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'customer',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  price REAL NOT NULL,
  old_price REAL,
  category TEXT NOT NULL,
  color TEXT,
  badge TEXT,
  image TEXT NOT NULL,
  description TEXT,
  stock INTEGER NOT NULL DEFAULT 10,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS cart_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  product_id INTEGER NOT NULL,
  size TEXT NOT NULL,
  qty INTEGER NOT NULL DEFAULT 1,
  UNIQUE(user_id, product_id, size),
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(product_id) REFERENCES products(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS wishlist_items (
  user_id INTEGER NOT NULL,
  product_id INTEGER NOT NULL,
  PRIMARY KEY(user_id, product_id),
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(product_id) REFERENCES products(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  total REAL NOT NULL,
  status TEXT NOT NULL DEFAULT 'Pending',
  address TEXT NOT NULL,
  phone TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS order_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_id INTEGER NOT NULL,
  product_id INTEGER NOT NULL,
  product_name TEXT NOT NULL,
  price REAL NOT NULL,
  size TEXT NOT NULL,
  qty INTEGER NOT NULL,
  FOREIGN KEY(order_id) REFERENCES orders(id) ON DELETE CASCADE
);
`);

const seedProducts = [
  ["Relaxed Linen Shirt",2499,2999,"Shirts","Sand","New","https://images.unsplash.com/photo-1603252109303-2751441dd157?auto=format&fit=crop&w=900&q=85","Breathable linen blend with a relaxed premium silhouette.",20],
  ["Textured Resort Shirt",2199,2599,"Shirts","Olive","New","https://images.unsplash.com/photo-1598033129183-c4f50c736f10?auto=format&fit=crop&w=900&q=85","Textured resort shirt made for effortless summer styling.",18],
  ["Essential Overshirt",2899,3399,"Overshirts","Black","Bestseller","https://images.unsplash.com/photo-1551028719-00167b16eac5?auto=format&fit=crop&w=900&q=85","Structured overshirt with a clean contemporary finish.",14],
  ["Straight Fit Trousers",2399,2799,"Trousers","Charcoal","","https://images.unsplash.com/photo-1624378439575-d8705ad7ae80?auto=format&fit=crop&w=900&q=85","Straight-fit trousers with an elevated everyday drape.",22],
  ["Premium Cotton Tee",1499,1799,"T-Shirts","White","Bestseller","https://images.unsplash.com/photo-1521572163474-6864f9cf17ab?auto=format&fit=crop&w=900&q=85","Heavyweight premium cotton essential tee.",30],
  ["Classic Oxford Shirt",2299,2699,"Shirts","Blue","","https://images.unsplash.com/photo-1596755389378-c31d21fd1273?auto=format&fit=crop&w=900&q=85","Classic Oxford construction with a modern regular fit.",16],
  ["Relaxed Pleated Trouser",2599,2999,"Trousers","Beige","New","https://images.unsplash.com/photo-1473966968600-fa801b869a1a?auto=format&fit=crop&w=900&q=85","Pleated trousers with a relaxed, refined silhouette.",15],
  ["Cotton Kurta",1999,2399,"Ethnic","Ivory","Festive","https://images.unsplash.com/photo-1610030469983-98e550d6193c?auto=format&fit=crop&w=900&q=85","Contemporary cotton kurta for festive and occasion dressing.",24]
];

const count = db.prepare("SELECT COUNT(*) AS c FROM products").get().c;
if (!count) {
  const insert = db.prepare(`INSERT INTO products
    (name,price,old_price,category,color,badge,image,description,stock)
    VALUES (?,?,?,?,?,?,?,?,?)`);
  const tx = db.transaction(rows => rows.forEach(r => insert.run(...r)));
  tx(seedProducts);
}

const adminEmail = "admin@mahira.com";
if (!db.prepare("SELECT id FROM users WHERE email=?").get(adminEmail)) {
  db.prepare("INSERT INTO users(name,email,password,role) VALUES(?,?,?,?)")
    .run("MAHIRA Admin", adminEmail, bcrypt.hashSync("Admin@123", 10), "admin");
}

function auth(req,res,next) {
  if (!req.session.user) return res.status(401).json({error:"Please login first."});
  next();
}
function admin(req,res,next) {
  if (!req.session.user || req.session.user.role !== "admin")
    return res.status(403).json({error:"Admin access required."});
  next();
}
function publicUser(u) {
  return u ? {id:u.id,name:u.name,email:u.email,role:u.role} : null;
}

app.get("/api/me", (req,res) => res.json({user: publicUser(req.session.user)}));

app.post("/api/signup", async (req,res) => {
  const {name,email,password} = req.body;
  if (!name || !email || !password || password.length < 6)
    return res.status(400).json({error:"Name, email and a password of at least 6 characters are required."});
  try {
    const hash = await bcrypt.hash(password, 10);
    const result = db.prepare("INSERT INTO users(name,email,password) VALUES(?,?,?)")
      .run(name.trim(), email.trim().toLowerCase(), hash);
    const user = db.prepare("SELECT id,name,email,role FROM users WHERE id=?").get(result.lastInsertRowid);
    req.session.user = user;
    res.json({user});
  } catch {
    res.status(409).json({error:"That email is already registered."});
  }
});

app.post("/api/login", async (req,res) => {
  const {email,password} = req.body;
  const user = db.prepare("SELECT * FROM users WHERE email=?").get((email||"").trim().toLowerCase());
  if (!user || !(await bcrypt.compare(password||"", user.password)))
    return res.status(401).json({error:"Invalid email or password."});
  req.session.user = publicUser(user);
  res.json({user:req.session.user});
});

app.post("/api/logout", (req,res) => req.session.destroy(() => res.json({ok:true})));

app.get("/api/products", (req,res) => {
  const {q,category} = req.query;
  let rows = db.prepare("SELECT * FROM products ORDER BY id DESC").all();
  if (q) {
    const s=q.toLowerCase();
    rows=rows.filter(p => `${p.name} ${p.category} ${p.color}`.toLowerCase().includes(s));
  }
  if (category) rows=rows.filter(p => p.category.toLowerCase()===category.toLowerCase());
  res.json(rows);
});
app.get("/api/products/:id", (req,res) => {
  const p=db.prepare("SELECT * FROM products WHERE id=?").get(req.params.id);
  p ? res.json(p) : res.status(404).json({error:"Product not found"});
});

app.get("/api/cart", auth, (req,res) => {
  const rows=db.prepare(`
    SELECT c.product_id AS id,c.size,c.qty,p.name,p.price,p.old_price,p.image,p.stock
    FROM cart_items c JOIN products p ON p.id=c.product_id
    WHERE c.user_id=? ORDER BY c.id DESC`).all(req.session.user.id);
  const total=rows.reduce((s,x)=>s+x.price*x.qty,0);
  res.json({items:rows,total});
});
app.post("/api/cart", auth, (req,res) => {
  const {productId,size="M",qty=1}=req.body;
  const p=db.prepare("SELECT * FROM products WHERE id=?").get(productId);
  if (!p) return res.status(404).json({error:"Product not found."});
  const safeQty=Math.max(1,Math.min(Number(qty)||1,p.stock));
  db.prepare(`
    INSERT INTO cart_items(user_id,product_id,size,qty) VALUES(?,?,?,?)
    ON CONFLICT(user_id,product_id,size) DO UPDATE SET qty=MIN(qty+excluded.qty,?)
  `).run(req.session.user.id, productId, size, safeQty, p.stock);
  res.json({ok:true});
});
app.patch("/api/cart/:id", auth, (req,res) => {
  const qty=Math.max(1,Number(req.body.qty)||1);
  db.prepare("UPDATE cart_items SET qty=? WHERE user_id=? AND product_id=? AND size=?")
    .run(qty,req.session.user.id,req.params.id,req.body.size);
  res.json({ok:true});
});
app.delete("/api/cart/:id", auth, (req,res) => {
  db.prepare("DELETE FROM cart_items WHERE user_id=? AND product_id=? AND size=?")
    .run(req.session.user.id,req.params.id,req.body.size);
  res.json({ok:true});
});

app.get("/api/wishlist", auth, (req,res) => {
  res.json(db.prepare(`
    SELECT p.* FROM wishlist_items w JOIN products p ON p.id=w.product_id
    WHERE w.user_id=? ORDER BY p.id DESC`).all(req.session.user.id));
});
app.post("/api/wishlist/:id", auth, (req,res) => {
  const exists=db.prepare("SELECT 1 FROM wishlist_items WHERE user_id=? AND product_id=?").get(req.session.user.id,req.params.id);
  if (exists) db.prepare("DELETE FROM wishlist_items WHERE user_id=? AND product_id=?").run(req.session.user.id,req.params.id);
  else db.prepare("INSERT INTO wishlist_items(user_id,product_id) VALUES(?,?)").run(req.session.user.id,req.params.id);
  res.json({saved:!exists});
});

app.post("/api/orders", auth, (req,res) => {
  const {address,phone}=req.body;
  if (!address || !phone) return res.status(400).json({error:"Address and phone are required."});
  const items=db.prepare(`
    SELECT c.product_id AS id,c.size,c.qty,p.name,p.price,p.stock
    FROM cart_items c JOIN products p ON p.id=c.product_id WHERE c.user_id=?`).all(req.session.user.id);
  if (!items.length) return res.status(400).json({error:"Your cart is empty."});
  for (const i of items) if (i.qty > i.stock) return res.status(400).json({error:`Not enough stock for ${i.name}.`});
  const total=items.reduce((s,i)=>s+i.price*i.qty,0);
  const tx=db.transaction(() => {
    const order=db.prepare("INSERT INTO orders(user_id,total,address,phone) VALUES(?,?,?,?)")
      .run(req.session.user.id,total,address,phone);
    const oi=db.prepare("INSERT INTO order_items(order_id,product_id,product_name,price,size,qty) VALUES(?,?,?,?,?,?)");
    const stock=db.prepare("UPDATE products SET stock=stock-? WHERE id=?");
    items.forEach(i=>{oi.run(order.lastInsertRowid,i.id,i.name,i.price,i.size,i.qty);stock.run(i.qty,i.id);});
    db.prepare("DELETE FROM cart_items WHERE user_id=?").run(req.session.user.id);
    return order.lastInsertRowid;
  });
  res.json({orderId:tx()});
});

app.get("/api/orders", auth, (req,res) => {
  const orders=db.prepare("SELECT * FROM orders WHERE user_id=? ORDER BY id DESC").all(req.session.user.id);
  for (const o of orders) o.items=db.prepare("SELECT * FROM order_items WHERE order_id=?").all(o.id);
  res.json(orders);
});

/* Admin */
app.get("/api/admin/stats", admin, (req,res) => {
  res.json({
    users: db.prepare("SELECT COUNT(*) c FROM users WHERE role='customer'").get().c,
    products: db.prepare("SELECT COUNT(*) c FROM products").get().c,
    orders: db.prepare("SELECT COUNT(*) c FROM orders").get().c,
    revenue: db.prepare("SELECT COALESCE(SUM(total),0) s FROM orders").get().s
  });
});
app.get("/api/admin/products", admin, (req,res)=>res.json(db.prepare("SELECT * FROM products ORDER BY id DESC").all()));
app.post("/api/admin/products", admin, (req,res)=>{
  const p=req.body;
  const r=db.prepare(`INSERT INTO products(name,price,old_price,category,color,badge,image,description,stock)
    VALUES(?,?,?,?,?,?,?,?,?)`).run(p.name,Number(p.price),Number(p.old_price)||null,p.category,p.color||"",p.badge||"",p.image,p.description||"",Number(p.stock)||0);
  res.json({id:r.lastInsertRowid});
});
app.put("/api/admin/products/:id", admin, (req,res)=>{
  const p=req.body;
  db.prepare(`UPDATE products SET name=?,price=?,old_price=?,category=?,color=?,badge=?,image=?,description=?,stock=? WHERE id=?`)
    .run(p.name,Number(p.price),Number(p.old_price)||null,p.category,p.color||"",p.badge||"",p.image,p.description||"",Number(p.stock)||0,req.params.id);
  res.json({ok:true});
});
app.delete("/api/admin/products/:id", admin, (req,res)=>{
  db.prepare("DELETE FROM products WHERE id=?").run(req.params.id);
  res.json({ok:true});
});
app.get("/api/admin/orders", admin, (req,res)=>{
  const orders=db.prepare(`
    SELECT o.*,u.name,u.email FROM orders o JOIN users u ON u.id=o.user_id ORDER BY o.id DESC`).all();
  res.json(orders);
});
app.patch("/api/admin/orders/:id", admin, (req,res)=>{
  db.prepare("UPDATE orders SET status=? WHERE id=?").run(req.body.status,req.params.id);
  res.json({ok:true});
});

app.use(express.static(path.join(__dirname,"public")));
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));

app.listen(PORT, "0.0.0.0", () => {
  console.log(`MAHIRA MEN running on port ${PORT}`);
});