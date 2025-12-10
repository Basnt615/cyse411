const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const sqlite3 = require("sqlite3").verbose();
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");
const csurf = require("csurf");
const sanitizer = require("some-html-sanitizer");
const app = express();



// --- RATE LIMITER ---
const sensitiveLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,
  message: "Too many requests. Please try again later.",
});

// --- CORS ---
app.use(
  cors({
    origin: ["http://localhost:3001", "http://127.0.0.1:3001"],
    credentials: true,
  })
);

app.use(bodyParser.json());
app.use(cookieParser());
const csrfProtection = csurf({ cookie: true });

// --- SQLITE IN-MEMORY DB ---
const db = new sqlite3.Database(":memory:");

const bcrypt = require("bcrypt");

function secureHash(password) {
  return bcrypt.hashSync(password, 12); // 12 rounds recommended
}
function verifyPassword(password, hash) {
  return bcrypt.compareSync(password, hash);
}

db.serialize(() => {
  db.run(`
    CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password_hash TEXT,
      email TEXT
    )
  `);

  db.run(`
    CREATE TABLE transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      amount REAL,
      description TEXT
    )
  `);

  db.run(`
    CREATE TABLE feedback (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user TEXT,
      comment TEXT
    )
  `);

  const passwordHash = secureHash("password123");

  db.run(
    "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
    ["alice", passwordHash, "alice@example.com"]
  );

  db.run(
    "INSERT INTO transactions (user_id, amount, description) VALUES (?, ?, ?)",
    [1, 25.5, "Coffee shop"]
  );
  db.run(
    "INSERT INTO transactions (user_id, amount, description) VALUES (?, ?, ?)",
    [1, 100, "Groceries"]
  );
});

// --- SESSION STORE ---
const sessions = {};

function auth(req, res, next) {
  const sid = req.cookies.sid;
  if (!sid || !sessions[sid]) return res.status(401).json({ error: "Not authenticated" });
  req.user = { id: sessions[sid].userId };
  next();
}

// --- LOGIN ---
app.post("/login", sensitiveLimiter, csrfProtection, (req, res) => {
  const { username, password } = req.body;

  db.get("SELECT id, username, password_hash FROM users WHERE username = ?", [username], (err, user) => {
    if (!user) return res.status(404).json({ error: "Unknown username" });

    if (!verifyPassword(password, user.password_hash)) {
      return res.status(401).json({ error: "Wrong password" });
  }
    const sid = crypto.randomBytes(32).toString("hex");
    sessions[sid] = { userId: user.id };

    res.cookie("sid", sid, {}); // normal cookie (not HttpOnly)
    res.json({ success: true });
  });
});

// --- GET CURRENT USER ---
app.get("/me", auth, sensitiveLimiter, (req, res) => {
  db.get("SELECT username, email FROM users WHERE id = ?", [req.user.id], (err, row) => {
    if (err) return res.status(500).json({ error: "Database error" });
    res.json(row);
  });
});

// --- TRANSACTIONS ---
app.get("/transactions", auth, sensitiveLimiter, (req, res) => {
  const q = req.query.q || "";

  const sql = `
    SELECT id, amount, description
    FROM transactions
    WHERE user_id = ?
      AND description LIKE ?
    ORDER BY id DESC
  `;

  db.all(sql, [req.user.id, `%${q}%`], (err, rows) => {
    if (err) return res.status(500).json({ error: "Database error" });
    res.json(rows);
  });
});

// --- FEEDBACK ---
app.post("/feedback", auth, sensitiveLimiter, csrfProtection, (req, res) => {
  const comment = sanitizer.sanitize(req.body.comment);
  const userId = req.user.id;

  db.get("SELECT username FROM users WHERE id = ?", [userId], (err, row) => {
    if (err) return res.status(500).json({ error: "Database error" });
    if (!row) return res.status(404).json({ error: "User not found" });

    const username = row.username;
    db.run("INSERT INTO feedback (user, comment) VALUES (?, ?)", [username, comment], (err) => {
      if (err) return res.status(500).json({ error: "Failed to save feedback" });
      res.json({ success: true });
    });
  });
});

app.get("/feedback", auth, sensitiveLimiter, (req, res) => {
  db.all("SELECT user, comment FROM feedback ORDER BY id DESC", (err, rows) => {
    if (err) return res.status(500).json({ error: "Database error" });
    res.json(rows);
  });
});

// --- CHANGE EMAIL ---
app.post("/change-email", auth, sensitiveLimiter, csrfProtection, (req, res) => {
  const newEmail = req.body.email;
  if (!newEmail.includes("@")) return res.status(400).json({ error: "Invalid email" });

  db.run("UPDATE users SET email = ? WHERE id = ?", [newEmail, req.user.id], (err) => {
    if (err) return res.status(500).json({ error: "Database error" });
    res.json({ success: true, email: newEmail });
  });
});

// --- START SERVER ---
app.listen(4000, () =>
  console.log("FastBank Version A backend running on http://localhost:4000")
);
