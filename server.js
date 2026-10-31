const express = require("express");
const cors = require("cors");
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
  ssl:
    process.env.NODE_ENV === "production"
      ? { rejectUnauthorized: false }
      : false
});

app.set("trust proxy", 1);

const allowedOrigins = (process.env.FRONTEND_URL || "")
  .split(",")
  .map(origin => origin.trim())
  .filter(Boolean);

app.use(helmet());

app.use(
  cors({
    origin: function (origin, callback) {
      // Allows requests without an Origin header, such as direct browser testing
      if (!origin) {
        return callback(null, true);
      }

      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      console.error("Blocked frontend origin:", origin);
      return callback(new Error("Origin not allowed"));
    },
    credentials: true
  })
);

app.use(express.json({ limit: "20kb" }));

// Main backend test route
app.get("/", (req, res) => {
  res.send("TradersCheem backend is running");
});

// Health-check route
app.get("/health", (req, res) => {
  res.json({
    connected: true,
    status: "TradersCheem Backend is Running"
  });
});

// Optional alternative health URL
app.get("/api/health", (req, res) => {
  res.json({
    connected: true,
    status: "TradersCheem Backend is Running"
  });
});

// Serve frontend files only if you have a public folder
app.use(express.static("public"));

app.use(
  session({
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
  })
);
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
      account_type VARCHAR(10) NOT NULL CHECK (account_type IN ('DEMO', 'LIVE')),
      balance NUMERIC(15,2) NOT NULL DEFAULT 0.00,
      updated_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(user_id, account_type)
    );

    CREATE TABLE IF NOT EXISTS trades (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      account_type VARCHAR(10) NOT NULL CHECK (account_type IN ('DEMO', 'LIVE')),
      symbol VARCHAR(30) NOT NULL,
      direction VARCHAR(10) NOT NULL,
      stake NUMERIC(15,2) NOT NULL,
      payout NUMERIC(15,2) DEFAULT 0.00,
      result VARCHAR(20) NOT NULL CHECK (result IN ('WIN', 'LOSS', 'PENDING')),
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
}

function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: "Please log in first." });
  }
  next();
}

// REGISTER USER
app.post("/api/auth/register", async (req, res) => {
  try {
    const fullName = String(req.body.fullName || "").trim();
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (!fullName || !email || password.length < 10) {
      return res.status(400).json({
        error: "Enter your name, valid email and a password of at least 10 characters."
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      const userResult = await client.query(
        `INSERT INTO users (full_name, email, password_hash)
         VALUES ($1, $2, $3)
         RETURNING id, full_name, email`,
        [fullName, email, passwordHash]
      );

      const user = userResult.rows[0];

      await client.query(
        `INSERT INTO trading_accounts (user_id, account_type, balance)
         VALUES ($1, 'DEMO', 100000.00)`,
        [user.id]
      );

      await client.query(
        `INSERT INTO trading_accounts (user_id, account_type, balance)
         VALUES ($1, 'LIVE', 0.00)`,
        [user.id]
      );

      await client.query("COMMIT");

      req.session.userId = user.id;

      res.status(201).json({
        message: "Account created successfully.",
        user: { id: user.id, fullName: user.full_name, email: user.email }
      });
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({ error: "This email is already registered." });
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
      `SELECT id, full_name, email, password_hash FROM users WHERE email = $1`,
      [email]
    );

    if (
      !result.rows.length ||
      !(await bcrypt.compare(password, result.rows[0].password_hash))
    ) {
      return res.status(401).json({ error: "Incorrect email or password." });
    }

    const user = result.rows[0];

    req.session.regenerate(error => {
      if (error) return res.status(500).json({ error: "Login failed." });

      req.session.userId = user.id;

      req.session.save(error => {
        if (error) return res.status(500).json({ error: "Login failed." });

        res.json({
          message: "Login successful.",
          user: { id: user.id, fullName: user.full_name, email: user.email }
        });
      });
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Login failed." });
  }
});

// CURRENT USER
app.get("/api/auth/me", requireLogin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, full_name, email FROM users WHERE id = $1`,
      [req.session.userId]
    );

    if (!result.rows.length) {
      return res.status(404).json({ error: "User not found." });
    }

    const user = result.rows[0];

    res.json({
      user: { id: user.id, fullName: user.full_name, email: user.email }
    });
  } catch (error) {
    res.status(500).json({ error: "Could not load account." });
  }
});

// LOGOUT
app.post("/api/auth/logout", requireLogin, (req, res) => {
  req.session.destroy(error => {
    if (error) return res.status(500).json({ error: "Logout failed." });

    res.clearCookie("traderscheem.sid");
    res.json({ message: "Logged out successfully." });
  });
});

// GET BALANCES
app.get("/api/trading/balances", requireLogin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT account_type, balance FROM trading_accounts WHERE user_id = $1`,
      [req.session.userId]
    );

    const balances = { DEMO: 0, LIVE: 0 };
    result.rows.forEach(row => {
      balances[row.account_type] = parseFloat(row.balance);
    });

    res.json({ balances });
  } catch (error) {
    res.status(500).json({ error: "Could not load balances." });
  }
});

// EXECUTE TRADE
app.post("/api/trading/trade", requireLogin, async (req, res) => {
  const accountType = (req.body.accountType || "DEMO").toUpperCase();
  const symbol = String(req.body.symbol || "").trim();
  const direction = String(req.body.direction || "").toUpperCase();
  const stake = parseFloat(req.body.stake);
  const resultType = String(req.body.result || "WIN").toUpperCase();
  const profitMargin = 0.85;

  if (!["DEMO", "LIVE"].includes(accountType)) {
    return res.status(400).json({ error: "Invalid account type." });
  }

  if (!symbol || isNaN(stake) || stake <= 0) {
    return res.status(400).json({ error: "Invalid trade symbol or stake amount." });
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const accountResult = await client.query(
      `SELECT balance FROM trading_accounts 
       WHERE user_id = $1 AND account_type = $2 FOR UPDATE`,
      [req.session.userId, accountType]
    );

    if (!accountResult.rows.length) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Trading account not found." });
    }

    const currentBalance = parseFloat(accountResult.rows[0].balance);

    if (currentBalance < stake) {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: "Insufficient funds for this trade." });
    }

    let payout = 0;
    let balanceChange = -stake;

    if (resultType === "WIN") {
      payout = stake + (stake * profitMargin);
      balanceChange = stake * profitMargin;
    }

    const updatedBalance = currentBalance + balanceChange;

    await client.query(
      `UPDATE trading_accounts 
       SET balance = $1, updated_at = NOW() 
       WHERE user_id = $2 AND account_type = $3`,
      [updatedBalance, req.session.userId, accountType]
    );

    const tradeResult = await client.query(
      `INSERT INTO trades (user_id, account_type, symbol, direction, stake, payout, result)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING id, symbol, direction, stake, payout, result, created_at`,
      [req.session.userId, accountType, symbol, direction, stake, payout, resultType]
    );

    await client.query("COMMIT");

    res.json({
      message: "Trade executed successfully.",
      newBalance: updatedBalance,
      trade: tradeResult.rows[0]
    });
  } catch (error) {
    await client.query("ROLLBACK");
    console.error(error);
    res.status(500).json({ error: "Trade execution failed." });
  } finally {
    client.release();
  }
});

// GET TRADE HISTORY
app.get("/api/trading/trades", requireLogin, async (req, res) => {
  try {
    const accountType = (req.query.type || "DEMO").toUpperCase();

    if (!["DEMO", "LIVE"].includes(accountType)) {
      return res.status(400).json({ error: "Invalid account type." });
    }

    const result = await pool.query(
      `SELECT id, symbol, direction, stake, payout, result, created_at
       FROM trades
       WHERE user_id = $1 AND account_type = $2
       ORDER BY created_at DESC
       LIMIT 100`,
      [req.session.userId, accountType]
    );

    res.json({ accountType, trades: result.rows });
  } catch (error) {
    res.status(500).json({ error: "Could not load trade history." });
  }
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: "Server error." });
});

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
