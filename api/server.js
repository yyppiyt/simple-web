const express = require("express");
const crypto = require("crypto");
const { Pool } = require("pg");
const QRCode = require("qrcode");

const app = express();
const port = 3000;
const sessionDays = 7;
const passwordIterations = 120000;
const passwordKeyLength = 32;
const passwordDigest = "sha256";
const minimumPasswordLength = 8;
const maximumPasswordLength = 128;
const twoFactorChallengeMinutes = 5;
const commonPasswordValues = [
  "00000000",
  "11111111",
  "123456",
  "1234567",
  "12345678",
  "123456789",
  "1234567890",
  "1q2w3e4r",
  "1qaz2wsx",
  "abc123",
  "abc12345",
  "admin",
  "admin123",
  "baseball",
  "dragon",
  "football",
  "iloveyou",
  "letmein",
  "login",
  "master",
  "monkey",
  "monkey123",
  "p@ssw0rd",
  "passw0rd",
  "password",
  "password1",
  "password123",
  "princess",
  "qwerty",
  "qwerty1",
  "qwerty123",
  "qwertyuiop",
  "shadow",
  "sunshine",
  "superman",
  "trustno1",
  "welcome",
  "welcome1",
  "zaq12wsx",
];

app.use(express.json({ limit: "1mb" }));

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

  await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret TEXT");
  await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN NOT NULL DEFAULT FALSE");
  await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_data TEXT");

  await pool.query(`
    CREATE TABLE IF NOT EXISTS two_factor_challenges (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash TEXT NOT NULL UNIQUE,
      expires_at TIMESTAMP NOT NULL,
      attempts_remaining INTEGER NOT NULL DEFAULT 5,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);
  await pool.query("ALTER TABLE two_factor_challenges ADD COLUMN IF NOT EXISTS attempts_remaining INTEGER NOT NULL DEFAULT 5");

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

function normalizePasswordText(value) {
  return String(value).normalize("NFKC").toLowerCase();
}

function getCommonPasswordKeys(value) {
  const normalized = normalizePasswordText(value);
  const alphaNumeric = normalized.replace(/[^a-z0-9]/g, "");
  const deLeeted = normalized
    .replace(/[@4]/g, "a")
    .replace(/3/g, "e")
    .replace(/0/g, "o")
    .replace(/[$5]/g, "s")
    .replace(/7/g, "t")
    .replace(/[^a-z0-9]/g, "");

  return [...new Set([normalized, alphaNumeric, deLeeted])];
}

const commonPasswordKeys = new Set(
  commonPasswordValues.flatMap(getCommonPasswordKeys)
);

function getPasswordRequirements(password, username) {
  const normalizedPassword = normalizePasswordText(password);
  const normalizedUsername = normalizePasswordText(username);
  const passwordLength = Array.from(password).length;
  const common = getCommonPasswordKeys(password).some((key) =>
    commonPasswordKeys.has(key)
  );

  return {
    username:
      Boolean(password) &&
      (!normalizedUsername || !normalizedPassword.includes(normalizedUsername)),
    mixedCase: /\p{Ll}/u.test(password) && /\p{Lu}/u.test(password),
    number: /\p{N}/u.test(password),
    special: /[\p{P}\p{S}]/u.test(password),
    common: Boolean(password) && !common,
    length: passwordLength >= minimumPasswordLength,
    maximumLength: passwordLength <= maximumPasswordLength,
  };
}

function getPasswordRequirementError(requirements) {
  const messages = {
    username: "must not contain the username",
    mixedCase: "must contain uppercase and lowercase letters",
    number: "must contain a number",
    special: "must contain a special character",
    common: "must not be a commonly used password",
    length: `must be at least ${minimumPasswordLength} characters`,
    maximumLength: `must be no more than ${maximumPasswordLength} characters`,
  };
  const failures = Object.entries(requirements)
    .filter(([, met]) => !met)
    .map(([name]) => messages[name]);

  return failures.length > 0
    ? `password ${failures.join("; ")}`
    : "";
}

function getMessage(message) {
  return typeof message === "string" ? message.trim() : "";
}

function publicUser(user) {
  return {
    id: user.id,
    username: user.username,
    created_at: user.created_at,
    two_factor_enabled: Boolean(user.totp_enabled),
    avatar_data: user.avatar_data || null,
  };
}

const base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Encode(buffer) {
  let bits = "";
  for (const byte of buffer) bits += byte.toString(2).padStart(8, "0");
  let result = "";
  for (let i = 0; i < bits.length; i += 5) {
    result += base32Alphabet[parseInt(bits.slice(i, i + 5).padEnd(5, "0"), 2)];
  }
  return result;
}

function base32Decode(value) {
  const clean = String(value).toUpperCase().replace(/[^A-Z2-7]/g, "");
  let bits = "";
  for (const char of clean) {
    const index = base32Alphabet.indexOf(char);
    if (index < 0) return Buffer.alloc(0);
    bits += index.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}

function totpCode(secret, counter) {
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(BigInt(counter));
  const digest = crypto.createHmac("sha1", base32Decode(secret)).update(counterBuffer).digest();
  const offset = digest[digest.length - 1] & 15;
  const number = (digest.readUInt32BE(offset) & 0x7fffffff) % 1000000;
  return String(number).padStart(6, "0");
}

function verifyTotp(secret, code) {
  if (!/^\d{6}$/.test(String(code || ""))) return false;
  const counter = Math.floor(Date.now() / 30000);
  return [-1, 0, 1].some((window) => {
    const expected = Buffer.from(totpCode(secret, counter + window));
    const supplied = Buffer.from(String(code));
    return expected.length === supplied.length && crypto.timingSafeEqual(expected, supplied);
  });
}

async function createTwoFactorChallenge(userId) {
  const token = crypto.randomBytes(32).toString("hex");
  const expiresAt = new Date(Date.now() + twoFactorChallengeMinutes * 60 * 1000);
  await pool.query("DELETE FROM two_factor_challenges WHERE expires_at <= NOW() OR user_id = $1", [userId]);
  await pool.query(
    "INSERT INTO two_factor_challenges (user_id, token_hash, expires_at) VALUES ($1, $2, $3)",
    [userId, hashToken(token), expiresAt]
  );
  return { token, expires_at: expiresAt };
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

async function createSession(userId, executor = pool) {
  const token = crypto.randomBytes(32).toString("hex");
  const tokenHash = hashToken(token);
  const expiresAt = getSessionExpiry();

  await executor.query("DELETE FROM user_sessions WHERE expires_at <= NOW()");

  const result = await executor.query(
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
        users.created_at,
        users.totp_enabled,
        users.avatar_data
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

app.get("/messages", requireAuth, async (req, res) => {
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

app.post("/auth/register", async (req, res, next) => {
  try {
    const username = normalizeUsername(req.body?.username);
    const password = getPassword(req.body?.password);

    if (!validateUsername(username)) {
      return res.status(400).json({
        error: "username must be 3-32 characters: letters, numbers, or underscore",
      });
    }

    const passwordRequirements = getPasswordRequirements(password, username);
    const passwordError = getPasswordRequirementError(passwordRequirements);

    if (passwordError) {
      return res.status(400).json({
        error: passwordError,
        code: "PASSWORD_REQUIREMENTS",
        requirements: passwordRequirements,
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

    next(err);
  }
});

app.post("/auth/login", async (req, res, next) => {
  let client = null;
  let transactionOpen = false;

  try {
    const username = normalizeUsername(req.body?.username);
    const password = getPassword(req.body?.password);

    const result = await pool.query(
      "SELECT id, username, password_hash, created_at, totp_secret, totp_enabled FROM users WHERE username = $1",
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
    if (userRow.totp_enabled) {
      const challenge = await createTwoFactorChallenge(user.id);
      return res.json({
        requires_2fa: true,
        challenge_token: challenge.token,
        expires_at: challenge.expires_at,
      });
    }

    client = await pool.connect();
    await client.query("BEGIN");
    transactionOpen = true;

    const lockedUserResult = await client.query(
      `SELECT password_hash
       FROM users
       WHERE id = $1
       FOR UPDATE`,
      [user.id]
    );

    if (
      lockedUserResult.rows.length === 0 ||
      lockedUserResult.rows[0].password_hash !== userRow.password_hash
    ) {
      await client.query("ROLLBACK");
      transactionOpen = false;

      return res.status(401).json({
        error: "invalid username or password",
      });
    }

    const session = await createSession(user.id, client);
    await client.query("COMMIT");
    transactionOpen = false;

    res.json({
      user,
      token: session.token,
      expires_at: session.expires_at,
    });
  } catch (err) {
    if (client && transactionOpen) {
      try {
        await client.query("ROLLBACK");
      } catch (rollbackError) {
        console.error("Failed to roll back login", rollbackError);
      }
    }

    next(err);
  } finally {
    client?.release();
  }
});

app.post("/auth/2fa/verify", async (req, res, next) => {
  let client = null;
  try {
    const challengeToken = typeof req.body?.challengeToken === "string" ? req.body.challengeToken : "";
    const code = String(req.body?.code || "").trim();
    const result = await pool.query(
      `SELECT two_factor_challenges.id AS challenge_id, users.*
       FROM two_factor_challenges
       JOIN users ON users.id = two_factor_challenges.user_id
       WHERE two_factor_challenges.token_hash = $1
         AND two_factor_challenges.expires_at > NOW()
         AND two_factor_challenges.attempts_remaining > 0`,
      [hashToken(challengeToken)]
    );
    if (!challengeToken || result.rows.length === 0) {
      return res.status(401).json({ error: "verification expired; please log in again", code: "CHALLENGE_EXPIRED" });
    }
    const row = result.rows[0];
    if (!row.totp_enabled || !row.totp_secret || !verifyTotp(row.totp_secret, code)) {
      await pool.query(
        "UPDATE two_factor_challenges SET attempts_remaining = attempts_remaining - 1 WHERE id = $1",
        [row.challenge_id]
      );
      return res.status(401).json({ error: "invalid verification code", code: "INVALID_TOTP" });
    }
    client = await pool.connect();
    await client.query("BEGIN");
    const deleted = await client.query("DELETE FROM two_factor_challenges WHERE id = $1 RETURNING id", [row.challenge_id]);
    if (deleted.rows.length === 0) {
      await client.query("ROLLBACK");
      return res.status(401).json({ error: "verification already used; please log in again" });
    }
    const session = await createSession(row.id, client);
    await client.query("COMMIT");
    res.json({ user: publicUser(row), token: session.token, expires_at: session.expires_at });
  } catch (err) {
    if (client) { try { await client.query("ROLLBACK"); } catch (_) {} }
    next(err);
  } finally { client?.release(); }
});

app.post("/auth/2fa/setup", requireAuth, async (req, res, next) => {
  try {
    const secret = base32Encode(crypto.randomBytes(20));
    const update = await pool.query(
      "UPDATE users SET totp_secret = $1 WHERE id = $2 AND totp_enabled = FALSE RETURNING id",
      [secret, req.user.id]
    );
    if (update.rows.length === 0) {
      return res.status(409).json({ error: "disable existing 2FA before starting a new setup" });
    }
    const label = encodeURIComponent(`Simple Web:${req.user.username}`);
    const issuer = encodeURIComponent("Simple Web");
    const uri = `otpauth://totp/${label}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`;
    const qr_code = await QRCode.toDataURL(uri, { errorCorrectionLevel: "M", margin: 2, width: 240 });
    res.json({ secret, uri, qr_code });
  } catch (err) { next(err); }
});

app.post("/auth/2fa/enable", requireAuth, async (req, res, next) => {
  try {
    const result = await pool.query("SELECT totp_secret FROM users WHERE id = $1", [req.user.id]);
    const secret = result.rows[0]?.totp_secret;
    if (!secret) return res.status(400).json({ error: "start 2FA setup first" });
    if (!verifyTotp(secret, String(req.body?.code || "").trim())) {
      return res.status(400).json({ error: "invalid verification code" });
    }
    await pool.query("UPDATE users SET totp_enabled = TRUE WHERE id = $1", [req.user.id]);
    res.json({ message: "Two-factor authentication is now enabled." });
  } catch (err) { next(err); }
});

app.post("/auth/2fa/disable", requireAuth, async (req, res, next) => {
  try {
    const result = await pool.query("SELECT totp_secret, totp_enabled FROM users WHERE id = $1", [req.user.id]);
    const row = result.rows[0];
    if (!row?.totp_enabled) return res.status(400).json({ error: "two-factor authentication is not enabled" });
    if (!verifyTotp(row.totp_secret, String(req.body?.code || "").trim())) {
      return res.status(400).json({ error: "invalid verification code" });
    }
    await pool.query("UPDATE users SET totp_secret = NULL, totp_enabled = FALSE WHERE id = $1", [req.user.id]);
    res.json({ message: "Two-factor authentication is now disabled." });
  } catch (err) { next(err); }
});

app.get("/auth/me", requireAuth, (req, res) => {
  res.json({
    user: req.user,
  });
});

app.put("/auth/avatar", requireAuth, async (req, res, next) => {
  try {
    const avatarData = typeof req.body?.avatarData === "string"
      ? req.body.avatarData
      : "";
    const match = avatarData.match(/^data:image\/(png|jpeg|webp);base64,([A-Za-z0-9+/]+={0,2})$/);

    if (!match) {
      return res.status(400).json({ error: "avatar must be a PNG, JPEG, or WebP image" });
    }

    const imageBytes = Buffer.from(match[2], "base64");
    if (imageBytes.length === 0 || imageBytes.length > 700 * 1024) {
      return res.status(400).json({ error: "avatar must be 700 KB or smaller" });
    }

    await pool.query("UPDATE users SET avatar_data = $1 WHERE id = $2", [avatarData, req.user.id]);
    res.json({ avatar_data: avatarData, message: "Profile icon updated." });
  } catch (err) {
    next(err);
  }
});

app.delete("/auth/avatar", requireAuth, async (req, res, next) => {
  try {
    await pool.query("UPDATE users SET avatar_data = NULL WHERE id = $1", [req.user.id]);
    res.json({ avatar_data: null, message: "Profile icon removed." });
  } catch (err) {
    next(err);
  }
});

app.post("/auth/change-password", requireAuth, async (req, res, next) => {
  let client = null;
  let transactionOpen = false;

  try {
    const currentPassword = getPassword(req.body?.currentPassword);
    const newPassword = getPassword(req.body?.newPassword);

    if (!currentPassword) {
      return res.status(400).json({
        error: "current password is required",
        code: "CURRENT_PASSWORD_REQUIRED",
      });
    }

    const requirements = getPasswordRequirements(
      newPassword,
      req.user.username
    );
    const passwordError = getPasswordRequirementError(requirements);

    if (passwordError) {
      return res.status(400).json({
        error: passwordError,
        code: "PASSWORD_REQUIREMENTS",
        requirements,
      });
    }

    const userResult = await pool.query(
      "SELECT password_hash FROM users WHERE id = $1",
      [req.user.id]
    );

    if (userResult.rows.length === 0) {
      return res.status(409).json({
        error: "account changed; please reload and try again",
        code: "ACCOUNT_CHANGED",
      });
    }

    const currentPasswordHash = userResult.rows[0].password_hash;
    const currentPasswordMatches = await verifyPassword(
      currentPassword,
      currentPasswordHash
    );

    if (!currentPasswordMatches) {
      return res.status(403).json({
        error: "current password is incorrect",
        code: "CURRENT_PASSWORD_INVALID",
      });
    }

    const passwordIsUnchanged = newPassword === currentPassword;

    if (passwordIsUnchanged) {
      return res.status(400).json({
        error: "new password must be different from the current password",
        code: "PASSWORD_UNCHANGED",
      });
    }

    const newPasswordHash = await hashPassword(newPassword);
    client = await pool.connect();
    await client.query("BEGIN");
    transactionOpen = true;

    const updateResult = await client.query(
      `UPDATE users
       SET password_hash = $1
       WHERE id = $2 AND password_hash = $3
       RETURNING id`,
      [newPasswordHash, req.user.id, currentPasswordHash]
    );

    if (updateResult.rows.length === 0) {
      await client.query("ROLLBACK");
      transactionOpen = false;

      return res.status(409).json({
        error: "password changed in another request; please try again",
        code: "PASSWORD_CHANGED_RETRY",
      });
    }

    await client.query(
      "DELETE FROM user_sessions WHERE user_id = $1 AND id <> $2",
      [req.user.id, req.sessionId]
    );
    await client.query("COMMIT");
    transactionOpen = false;

    res.json({
      message: "Password changed. Other sessions have been signed out.",
    });
  } catch (err) {
    if (client && transactionOpen) {
      try {
        await client.query("ROLLBACK");
      } catch (rollbackError) {
        console.error("Failed to roll back password change", rollbackError);
      }
    }

    next(err);
  } finally {
    client?.release();
  }
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

app.get("/hello", requireAuth, (req, res) => {
  res.json({
    message: "Hello from API",
  });
});

app.post("/echo", requireAuth, (req, res) => {
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
