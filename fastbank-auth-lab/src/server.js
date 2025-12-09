const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const csurf = require("csurf");
const crypto = require("crypto");
// bcrypt is installed but NOT used in the vulnerable baseline:
const bcrypt = require("bcrypt");

const app = express();
const PORT = 3001;

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());
const csrfProtection = csurf({ cookie: true });
app.use(express.static("public"));

app.get("/api/csrf-token", csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});
/**
 * VULNERABLE FAKE USER DB
 * For simplicity, we start with a single user whose password is "password123".
 * In the vulnerable version, we hash with a fast hash (SHA-256-like).
 */
const users = [
  {
    id: 1,
    username: "student",
    // VULNERABLE: fast hash without salt
    passwordHash: bcrypt.hashSync("password123", 12) // students must replace this scheme with bcrypt
  }
];

// In-memory session store
const sessions = {}; // token -> { userId }

/**
 * VULNERABLE FAST HASH FUNCTION
 * Students MUST STOP using this and replace logic with bcrypt.
 */

// Helper: find user by username
function findUser(username) {
  return users.find((u) => u.username === username);
}

// Home API just to show who is logged in
app.get("/api/me", (req, res) => {
  const token = req.cookies.session;
  if (!token || !sessions[token]) {
    return res.status(401).json({ authenticated: false });
  }
  const session = sessions[token];
  const user = users.find((u) => u.id === session.userId);
  res.json({ authenticated: true, username: user.username });
});

/**
 * VULNERABLE LOGIN ENDPOINT
 * - Uses fastHash instead of bcrypt
 * - Error messages leak whether username exists
 * - Session token is simple and predictable
 * - Cookie lacks security flags
 */
app.post("/api/login", csrfProtection, async (req, res) => {
  const { username, password } = req.body;
  const user = findUser(username);

  // was vulnrable 
  if (!user) {
  return res.status(401).json({ success: false, message: "Invalid credentials" });
}
  const valid = await bcrypt.compare(password, user.passwordHash);
  
  if (!valid) {
    return res.status(401).json({ success: false, message: "Invalid credentials" });
  }

  // Strong random token
  const token = crypto.randomBytes(32).toString("hex");

  // Store session
  sessions[token] = { userId: user.id };

  // Secure cookie
  res.cookie("session", token, {
    httpOnly: true,
    secure: true,
    sameSite: "lax"
  });

  // CSRF token (double submit)
  const csrfToken = crypto.randomBytes(24).toString("hex");
  res.cookie("csrfToken", csrfToken, {
    httpOnly: false,
    secure: true,
    sameSite: "lax"
  });

  res.json({ success: true });
});

/**
 * LOGOUT
 */
app.post("/api/logout", csrfProtection, (req, res) => {
  const token = req.cookies.session;
  if (token && sessions[token]) {
    delete sessions[token];
  }
  res.clearCookie("session");
  res.clearCookie("csrfToken");
  res.json({ success: true });
});

app.listen(PORT, () => {
  console.log(`FastBank Auth Lab running at http://localhost:${PORT}`);
});
