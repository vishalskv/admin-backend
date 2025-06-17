// index.js
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const pool = require("./db");
require("dotenv").config();

const app = express();
const cors = require("cors");
app.use(express.json());

// 🧪 Test route
app.get("/", (req, res) => {
  res.send("API Working ✅");
});
app.use(cors({
  origin: "https://admin-six-nu-73.vercel.app/login", // WARNING: allows any origin
  credentials: true // You cannot use credentials with wildcard origin
}));
app.use(express.json());
// 📝 Register API
app.post("/register", async (req, res) => {
  const { email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  try {
    const result = await pool.query(
      "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
      [email, hashedPassword]
    );
    res.status(201).json({ message: "User registered", user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 🔐 Login API
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    const user = result.rows[0];

    if (!user) return res.status(400).json({ error: "Invalid email or password" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: "Invalid email or password" });
const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, {
  expiresIn: "1h"
});


    res.json({ message: "Login success", token });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// Start server
const PORT = process.env.PORT || 3002;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
