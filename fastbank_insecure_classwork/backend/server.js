const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const sqlite3 = require("sqlite3").verbose();
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");  // for rate limiting
const csurf = require("csurf");                   // for CSRF protection
const sanitizer = require("some-html-sanitizer"); // for XSS input 
const app = express();

const sensitiveLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,                   // max 5 requests per IP per window
  message: 'Too many requests. Please try again later.'
});

// --- BASIC CORS (clean, not vulnerable) ---
app.use(
  cors({
   origin: ["http://localhost:3001", "http://127.0.0.1:3001"],
    credentials: true
  })
);

app.use(bodyParser.json());
app.use(cookieParser());
const csrfProtection = csurf({ cookie: true })
// --- IN-MEMORY SQLITE DB (clean) ---
const db = new sqlite3.Database(":memory:");

db.serialize(() => {
  db.run(`
    CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password_hash TEXT,
      email TEXT
    );
  `);

  db.run(`
    CREATE TABLE transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      amount REAL,
      description TEXT
    );
  `);

  db.run(`
    CREATE TABLE feedback (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user TEXT,
      comment TEXT
    );
  `);

  const passwordHash = crypto.createHash("sha256").update("password123").digest("hex");

  db.run(`INSERT INTO users (username, password_hash, email)
          VALUES ('alice', '${passwordHash}', 'alice@example.com');`);

  db.run(`INSERT INTO transactions (user_id, amount, description) VALUES (1, 25.50, 'Coffee shop')`);
  db.run(`INSERT INTO transactions (user_id, amount, description) VALUES (1, 100, 'Groceries')`);
});

// --- SESSION STORE (simple, predictable token exactly like assignment) ---
const sessions = {};

function fastHash(pwd) {
  return crypto.createHash("sha256").update(pwd).digest("hex");
}

function auth(req, res, next) {
  const sid = req.cookies.sid;
  if (!sid || !sessions[sid]) return res.status(401).json({ error: "Not authenticated" });
  req.user = { id: sessions[sid].userId };
  next();
}

// ------------------------------------------------------------
// Q4 — AUTH ISSUE 1 & 2: SHA256 fast hash + SQLi in username.
// Q4 — AUTH ISSUE 3: Username enumeration.
// Q4 — AUTH ISSUE 4: Predictable sessionId.
// ------------------------------------------------------------
app.post("/login", sensitiveLimiter, csrfProtection, (req, res) => {
  const { username, password } = req.body;

  const sql = `SELECT id, username, password_hash FROM users WHERE username = ?`;

  db.get(sql, [username], (err, user) => {
    if (!user) return res.status(404).json({ error: "Unknown username" });

    const candidate = fastHash(password);
    if (candidate !== user.password_hash) {
      return res.status(401).json({ error: "Wrong password" });
    }

    const sid = crypto.randomBytes(32).toString("hex"); // secure random
    sessions[sid] = { userId: user.id };

    // Cookie is intentionally “normal” (not HttpOnly / secure)
    res.cookie("sid", sid, {});

    res.json({ success: true });
  });
});

// ------------------------------------------------------------
// /me — clean route, no vulnerabilities
// ------------------------------------------------------------
app.get("/me", auth, sensitiveLimiter, (req, res) => {
  db.get(`SELECT username, email FROM users WHERE id = ${req.user.id}`, (err, row) => {
    res.json(row);
  });
});

// ------------------------------------------------------------
// Q1 — SQLi in transaction search
// ------------------------------------------------------------
app.get("/transactions", auth, sensitiveLimiter, (req, res) => {
  const q = req.query.q || "";
  const sql = `
    SELECT id, amount, description
    FROM transactions
    WHERE user_id = ${req.user.id}
      AND description LIKE '%${q}%'
    ORDER BY id DESC
  `;
  db.all(sql, [req.user.id, `%${q}%`], (err, rows) => res.json(rows));
});

// ------------------------------------------------------------
// Q2 — Stored XSS + SQLi in feedback insert
// ------------------------------------------------------------
app.post("/feedback", auth, sensitiveLimiter, csrfProtection, (req, res) => {
  const comment = sanitizer.sanitize(req.body.comment); // sanitize input
  const userId = req.user.id;

  // Get the username of the current user
  db.get(`SELECT username FROM users WHERE id = ?`, [userId], (err, row) => {
    if (err) return res.status(500).json({ error: "Database error" });
    if (!row) return res.status(404).json({ error: "User not found" });

    const username = row.username;

    // Insert feedback securely using parameterized query
    const insert = `INSERT INTO feedback (user, comment) VALUES (?, ?)`;
    db.run(insert, [username, comment], (err) => {
      if (err) return res.status(500).json({ error: "Failed to save feedback" });
      res.json({ success: true });
    });
  });
});

app.get("/feedback", auth, sensitiveLimiter, (req, res) => {
  db.all("SELECT user, comment FROM feedback ORDER BY id DESC", (err, rows) => {
    res.json(rows);
  });
});

// ------------------------------------------------------------
// Q3 — CSRF + SQLi in email update
// ------------------------------------------------------------
app.post("/change-email", auth, sensitiveLimiter, csrfProtection, (req, res) => {
  const newEmail = req.body.email;

  if (!newEmail.includes("@")) return res.status(400).json({ error: "Invalid email" });

  const sql = `
    UPDATE users SET email = '${newEmail}' WHERE id = ${req.user.id}
  `;
  db.run(sql, () => {
    res.json({ success: true, email: newEmail });
  });
});

// ------------------------------------------------------------
app.listen(4000, () =>
  console.log("FastBank Version A backend running on http://localhost:4000")
);
