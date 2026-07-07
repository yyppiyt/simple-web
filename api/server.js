const express = require("express");

const app = express();
const port = 3000;

app.use(express.json());

app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    message: "API is running"
  });
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