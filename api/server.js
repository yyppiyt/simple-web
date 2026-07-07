const express = require("express");
const { Pool } = require("pg");

const app = express();
const port = 3000;

app.use(express.json());

const pool = new Pool({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

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

app.post("/messages", async (req, res) => {
  try {
    const { name, message } = req.body;

    if (!name || !message) {
      return res.status(400).json({
        error: "name and message are required",
      });
    }

    const result = await pool.query(
      "INSERT INTO messages (name, message) VALUES ($1, $2) RETURNING id, name, message, created_at",
      [name, message]
    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({
      error: err.message,
    });
  }
});

app.get("/hello", (req, res) => {
  res.json({
    message: "Hello from API"
  });
});

app.post("/echo", (req, res) => {
  res.json({
    received: req.body
  });
});

app.listen(port, "0.0.0.0", () => {
  console.log(`API listening on port ${port}`);
});