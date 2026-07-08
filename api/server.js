const express = require("express");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();
const port = 3000;
const sessionDays = 7;
const passwordIterations = 120000;
const passwordKeyLength = 32;
const passwordDigest = "sha256";

app.use(express.json());

const pool = new Pool({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

async function ensureSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS messages (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      message TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS user_sessions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash TEXT NOT NULL UNIQUE,
      expires_at TIMESTAMP NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS user_sessions_user_id_idx
    ON user_sessions (user_id)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS user_sessions_expires_at_idx
    ON user_sessions (expires_at)
  `);
}

function normalizeUsername(username) {
  if (typeof username !== "string") {
    return "";
  }

  return username.trim();
}

function validateUsername(username) {
  return /^[a-zA-Z0-9_]{3,32}$/.test(username);
}

function getPassword(password) {
  return typeof password === "string" ? password : "";
}

function getMessage(message) {
  return typeof message === "string" ? message.trim() : "";
}

function publicUser(user) {
  return {
    id: user.id,
    username: user.username,
    created_at: user.created_at,
  };
}

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(
      password,
      salt,
      passwordIterations,
      passwordKeyLength,
      passwordDigest,
      (err, derivedKey) => {
        if (err) {
          reject(err);
          return;
        }

        resolve(
          `${passwordIterations}:${salt}:${derivedKey.toString("hex")}`
        );
      }
    );
  });
}

function verifyPassword(password, storedHash) {
  const [iterationsText, salt, originalHash] = String(storedHash).split(":");
  const iterations = Number(iterationsText);

  if (!iterations || !salt || !originalHash) {
    return Promise.resolve(false);
  }

  return new Promise((resolve, reject) => {
    crypto.pbkdf2(
      password,
      salt,
      iterations,
      passwordKeyLength,
      passwordDigest,
      (err, derivedKey) => {
        if (err) {
          reject(err);
          return;
        }

        const expectedHash = Buffer.from(originalHash, "hex");

        if (derivedKey.length !== expectedHash.length) {
          resolve(false);
          return;
        }

        resolve(crypto.timingSafeEqual(derivedKey, expectedHash));
      }
    );
  });
}

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function getSessionExpiry() {
  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + sessionDays);
  return expiresAt;
}

async function createSession(userId) {
  const token = crypto.randomBytes(32).toString("hex");
  const tokenHash = hashToken(token);
  const expiresAt = getSessionExpiry();

  await pool.query("DELETE FROM user_sessions WHERE expires_at <= NOW()");

  const result = await pool.query(
    `INSERT INTO user_sessions (user_id, token_hash, expires_at)
     VALUES ($1, $2, $3)
     RETURNING expires_at`,
    [userId, tokenHash, expiresAt]
  );

  return {
    token,
    expires_at: result.rows[0].expires_at,
  };
}

function getBearerToken(req) {
  const authorization = req.get("authorization") || "";
  const match = authorization.match(/^Bearer\s+(.+)$/i);
  return match ? match[1].trim() : "";
}

async function requireAuth(req, res, next) {
  try {
    const token = getBearerToken(req);

    if (!token) {
      return res.status(401).json({
        error: "login required",
      });
    }

    const result = await pool.query(
      `SELECT
        user_sessions.id AS session_id,
        user_sessions.expires_at,
        users.id,
        users.username,
        users.created_at
       FROM user_sessions
       JOIN users ON users.id = user_sessions.user_id
       WHERE user_sessions.token_hash = $1`,
      [hashToken(token)]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        error: "invalid session",
      });
    }

    const session = result.rows[0];

    if (new Date(session.expires_at) <= new Date()) {
      await pool.query("DELETE FROM user_sessions WHERE id = $1", [
        session.session_id,
      ]);

      return res.status(401).json({
        error: "session expired",
      });
    }

    req.sessionId = session.session_id;
    req.user = publicUser(session);
    next();
  } catch (err) {
    next(err);
  }
}

app.get("/health", async (req, res) => {
  try {
    const dbResult = await pool.query("SELECT NOW() AS now");

    res.json({
      status: "ok",
      api: "running",
      database: "connected",
      database_time: dbResult.rows[0].now,
    });
  } catch (err) {
    res.status(500).json({
      status: "error",
      api: "running",
      database: "not connected",
      error: err.message,
    });
  }
});

app.get("/messages", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, name, message, created_at FROM messages ORDER BY id DESC"
    );

    res.json(result.rows);
  } catch (err) {
    res.status(500).json({
      error: err.message,
    });
  }
});

app.post("/messages", requireAuth, async (req, res) => {
  try {
    const message = getMessage(req.body.message);

    if (!message) {
      return res.status(400).json({
        error: "message is required",
      });
    }

    if (message.length > 1000) {
      return res.status(400).json({
        error: "message must be 1000 characters or fewer",
      });
    }

    const result = await pool.query(
      "INSERT INTO messages (name, message) VALUES ($1, $2) RETURNING id, name, message, created_at",
      [req.user.username, message]
    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({
      error: err.message,
    });
  }
});

app.post("/auth/register", async (req, res) => {
  try {
    const username = normalizeUsername(req.body.username);
    const password = getPassword(req.body.password);

    if (!validateUsername(username)) {
      return res.status(400).json({
        error: "username must be 3-32 characters: letters, numbers, or underscore",
      });
    }

    if (password.length < 8 || password.length > 128) {
      return res.status(400).json({
        error: "password must be 8-128 characters",
      });
    }

    const passwordHash = await hashPassword(password);
    const result = await pool.query(
      `INSERT INTO users (username, password_hash)
       VALUES ($1, $2)
       RETURNING id, username, created_at`,
      [username, passwordHash]
    );
    const user = publicUser(result.rows[0]);
    const session = await createSession(user.id);

    res.status(201).json({
      user,
      token: session.token,
      expires_at: session.expires_at,
    });
  } catch (err) {
    if (err.code === "23505") {
      return res.status(409).json({
        error: "username already exists",
      });
    }

    res.status(500).json({
      error: err.message,
    });
  }
});

app.post("/auth/login", async (req, res) => {
  try {
    const username = normalizeUsername(req.body.username);
    const password = getPassword(req.body.password);

    const result = await pool.query(
      "SELECT id, username, password_hash, created_at FROM users WHERE username = $1",
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        error: "invalid username or password",
      });
    }

    const userRow = result.rows[0];
    const passwordMatches = await verifyPassword(
      password,
      userRow.password_hash
    );

    if (!passwordMatches) {
      return res.status(401).json({
        error: "invalid username or password",
      });
    }

    const user = publicUser(userRow);
    const session = await createSession(user.id);

    res.json({
      user,
      token: session.token,
      expires_at: session.expires_at,
    });
  } catch (err) {
    res.status(500).json({
      error: err.message,
    });
  }
});

app.get("/auth/me", requireAuth, (req, res) => {
  res.json({
    user: req.user,
  });
});

app.post("/auth/logout", requireAuth, async (req, res) => {
  try {
    await pool.query("DELETE FROM user_sessions WHERE id = $1", [
      req.sessionId,
    ]);

    res.status(204).send();
  } catch (err) {
    res.status(500).json({
      error: err.message,
    });
  }
});

app.get("/hello", (req, res) => {
  res.json({
    message: "Hello from API",
  });
});

app.post("/echo", (req, res) => {
  res.json({
    received: req.body,
  });
});

app.use((err, req, res, next) => {
  console.error(err);

  res.status(500).json({
    error: "internal server error",
  });
});

ensureSchema()
  .then(() => {
    app.listen(port, "0.0.0.0", () => {
      console.log(`API listening on port ${port}`);
    });
  })
  .catch((err) => {
    console.error("Failed to initialize database schema", err);
    process.exit(1);
  });