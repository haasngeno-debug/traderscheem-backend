const
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const helmet = require("helmet");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const pgSession = require("connect-pg-simple")(session);
const { Pool } = require("pg");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 10000;

if (!process.env.DATABASE_URL || !process.env.SESSION_SECRET) {
  console.error("Missing DATABASE_URL or SESSION_SECRET");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production"
    ? { rejectUnauthorized: false }
    : false
});

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || "smtp.gmail.com",
  port: Number(process.env.SMTP_PORT || 587),
  secure: process.env.SMTP_SECURE === "true",
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

app.set("trust proxy", 1);

const allowedOrigins = (process.env.FRONTEND_URL || "")
  .split(",")
  .map(origin => origin.trim())
  .filter(Boolean);

app.use(helmet());

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    callback(new Error("Origin not allowed"));
  },
  credentials: true
}));

app.use(express.json({ limit: "20kb" }));
app.use(express.static("public"));

app.use(session({
  store: new pgSession({
    pool,
    tableName: "user_sessions",
    createTableIfMissing: true
  }),
  name: "traderscheem.sid",
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
    maxAge: 1000 * 60 * 60 * 24
  }
}));

// HEALTH CHECK
app.get("/", (req, res) => {
  res.send("TradersCheem backend is running");
});

app.get("/health", (req, res) => {
  res.json({ connected: true, status: "Backend is running" });
});

// DATABASE TABLES
async function createTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      full_name VARCHAR(100) NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS trading_accounts (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      account_type VARCHAR(10) NOT NULL
        CHECK (account_type IN ('DEMO', 'LIVE')),
      balance NUMERIC(15,2) NOT NULL DEFAULT 0.00,
      updated_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(user_id, account_type)
    );

    CREATE TABLE IF NOT EXISTS trades (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      account_type VARCHAR(10) NOT NULL
        CHECK (account_type IN ('DEMO', 'LIVE')),
      symbol VARCHAR(30) NOT NULL,
      direction VARCHAR(10) NOT NULL,
      stake NUMERIC(15,2) NOT NULL,
      payout NUMERIC(15,2) DEFAULT 0.00,
      result VARCHAR(20) NOT NULL
        CHECK (result IN ('WIN', 'LOSS', 'PENDING')),
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS password_resets (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      token_hash TEXT NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
}

function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({
      error: "Please log in first."
    });
  }
  next();
}

// REGISTER
app.post("/api/auth/register", async (req, res) => {
  try {
    const fullName = String(req.body.fullName || "").trim();
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (!fullName || !email || password.length < 10) {
      return res.status(400).json({
        error: "Enter your name, email and a password of at least 10 characters."
      });
    }

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      const result = await client.query(
        `INSERT INTO users (full_name, email, password_hash)
         VALUES ($1, $2, $3)
         RETURNING id, full_name, email`,
        [fullName, email, await bcrypt.hash(password, 12)]
      );

      const user = result.rows[0];

      await client.query(
        `INSERT INTO trading_accounts
         (user_id, account_type, balance)
         VALUES ($1, 'DEMO', 100000.00), ($1, 'LIVE', 0.00)`,
        [user.id]
      );

      await client.query("COMMIT");

      req.session.userId = user.id;

      req.session.save(error => {
        if (error) {
          return res.status(500).json({ error: "Session creation failed." });
        }

        res.status(201).json({
          message: "Account created successfully.",
          user: {
            id: user.id,
            fullName: user.full_name,
            email: user.email
          }
        });
      });
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({
        error: "This email is already registered."
      });
    }

    console.error(error);
    res.status(500).json({ error: "Registration failed." });
  }
});

// LOGIN
app.post("/api/auth/login", async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    const result = await pool.query(
      "SELECT id, full_name, email, password_hash FROM users WHERE email = $1",
      [email]
    );

    if (
      !result.rows.length ||
      !(await bcrypt.compare(password, result.rows[0].password_hash))
    ) {
      return res.status(401).json({
        error: "Incorrect email or password."
      });
    }

    const user = result.rows[0];

    req.session.regenerate(error => {
      if (error) {
        return res.status(500).json({ error: "Login failed." });
      }

      req.session.userId = user.id;

      req.session.save(error => {
        if (error) {
          return res.status(500).json({ error: "Login failed." });
        }

        res.json({
          message: "Login successful.",
          user: {
            id: user.id,
            fullName: user.full_name,
            email: user.email
          }
        });
      });
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Login failed." });
  }
});

// FORGOT PASSWORD
app.post("/api/auth/forgot-password", async (req, res) => {
  const message =
    "If that email is registered, a password reset link will be sent.";

  try {
    const email = String(req.body.email || "").trim().toLowerCase();

    if (!email) {
      return res.status(400).json({ error: "Enter your email address." });
    }

    const frontendUrl = (process.env.FRONTEND_URL || "")
      .split(",")[0].trim().replace(/\/$/, "");

    if (
      !frontendUrl ||
      !process.env.SMTP_USER ||
      !process.env.SMTP_PASS
    ) {
      throw new Error("Email configuration is missing.");
    }

    const result = await pool.query(
      "SELECT id, email FROM users WHERE email = $1",
      [email]
    );

    if (!result.rows.length) {
      return res.json({ message });
    }

    const user = result.rows[0];

    const token = crypto.randomBytes(32).toString("hex");
    const tokenHash = crypto.createHash("sha256")
      .update(token).digest("hex");

    await pool.query(
      "DELETE FROM password_resets WHERE user_id = $1",
      [user.id]
    );

    await pool.query(
      `INSERT INTO password_resets
       (user_id, token_hash, expires_at)
       VALUES ($1, $2, NOW() + INTERVAL '30 minutes')`,
      [user.id, tokenHash]
    );

    const resetLink =
      `${frontendUrl}/reset-password.html?token=${token}`;

    await transporter.sendMail({
      from: process.env.SMTP_FROM || process.env.SMTP_USER,
      to: user.email,
      subject: "HassanFX Password Reset",
      text:
        `Use this link to reset your password. ` +
        `It expires in 30 minutes:\n${resetLink}`
    });

    res.json({ message });
  } catch (error) {
    console.error("Forgot password error:", error.message);
    res.status(500).json({
      error: "Could not send reset email. Please try again later."
    });
  }
});

// RESET PASSWORD
app.post("/api/auth/reset-password", async (req, res) => {
  const token = String(req.body.token || "");
  const password = String(req.body.password || "");

  if (!token || password.length < 10) {
    return res.status(400).json({
      error: "Enter a valid reset token and a password of at least 10 characters."
    });
  }

  let client;

  try {
    const tokenHash = crypto.createHash("sha256")
      .update(token).digest("hex");

    client = await pool.connect();
    await client.query("BEGIN");

    const result = await client.query(
      `SELECT id, user_id FROM password_resets
       WHERE token_hash = $1 AND expires_at > NOW()
       FOR UPDATE`,
      [tokenHash]
    );

    if (!result.rows.length) {
      await client.query("ROLLBACK");
      return res.status(400).json({
        error: "This reset link is invalid or expired."
      });
    }

    const userId = result.rows[0].user_id;
    const passwordHash = await bcrypt.hash(password, 12);

    await client.query(
      "UPDATE users SET password_hash = $1 WHERE id = $2",
      [passwordHash, userId]
    );

    await client.query(
      "DELETE FROM password_resets WHERE user_id = $1",
      [userId]
    );

    await client.query("COMMIT");

    res.json({
      message: "Password changed successfully. You can now log in."
    });
  } catch (error) {
    if (client) {
      await client.query("ROLLBACK").catch(() => {});
    }

    console.error("Reset password error:", error.message);
    res.status(500).json({
      error: "Could not reset your password."
    });
  } finally {
    if (client) client.release();
  }
});

// CURRENT USER
app.get("/api/auth/me", requireLogin, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, full_name, email FROM users WHERE id = $1",
      [req.session.userId]
    );

    if (!result.rows.length) {
      return res.status(404).json({ error: "User not found." });
    }

    const user = result.rows[0];

    res.json({
      user: {
        id: user.id,
        fullName: user.full_name,
        email: user.email
      }
    });
  } catch (error) {
    res.status(500).json({ error: "Could not load account." });
  }
});

// LOGOUT
app.post("/api/auth/logout", requireLogin, (req, res) => {
  req.session.destroy(error => {
    if (error) {
      return res.status(500).json({ error: "Logout failed." });
    }

    res.clearCookie("traderscheem.sid");
    res.json({ message: "Logged out successfully." });
  });
});

// GET ACCOUNT BALANCES
app.get("/api/trading/balances", requireLogin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT account_type, balance
       FROM trading_accounts WHERE user_id = $1`,
      [req.session.userId]
    );

    const balances = { DEMO: 0, LIVE: 0 };

    result.rows.forEach(row => {
      balances[row.account_type] = Number(row.balance);
    });

    res.json({ balances });
  } catch (error) {
    res.status(500).json({ error: "Could not load balances." });
  }
});

// GET TRADE HISTORY
app.get("/api/trading/trades", requireLogin, async (req, res) => {
  try {
    const accountType = String(req.query.type || "DEMO").toUpperCase();

    if (!["DEMO", "LIVE"].includes(accountType)) {
      return res.status(400).json({ error: "Invalid account type." });
    }

    const result = await pool.query(
      `SELECT id, symbol, direction, stake, payout, result, created_at
       FROM trades
       WHERE user_id = $1 AND account_type = $2
       ORDER BY created_at DESC LIMIT 100`,
      [req.session.userId, accountType]
    );

    res.json({ accountType, trades: result.rows });
  } catch (error) {
    res.status(500).json({ error: "Could not load trade history." });
  }
});

// REAL-MONEY TRADING IS NOT ENABLED
app.post("/api/trading/trade", requireLogin, (req, res) => {
  res.status(403).json({
    error: "Trading execution is currently disabled."
  });
});

// ERROR HANDLER
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: "Server error." });
});

// START SERVER
async function startServer() {
  try {
    await pool.query("SELECT NOW()");
    await createTables();

    app.listen(PORT, () => {
      console.log(`TradersCheem backend running on port ${PORT}`);
    });
  } catch (error) {
    console.error("Backend startup failed:", error);
    process.exit(1);
  }
}

startServer();
   
