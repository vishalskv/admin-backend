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
  origin: "*", // WARNING: allows any origin
  credentials: false // You cannot use credentials with wildcard origin
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
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).send("Missing fields");

    const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);

    if (result.rows.length === 0) return res.status(401).send("Invalid email");

    const user = result.rows[0];

    // ✅ Correct way to compare hashed password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).send("Invalid password");

    // ✅ Create a token if needed (optional)
    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET || "your_default_secret");

    res.status(200).json({ message: "Login successful", token });
  } catch (err) {
    console.error("Login Error:", err); // Log to see actual issue
    res.status(500).send("Server error");
  }
});

app.get("/init", async (req, res) => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
      )
    `);
    res.send("✅ Users table created");
  } catch (err) {
    console.error(err);
    res.status(500).send("Error creating table");
  }
});


app.use(express.json());

// Start server
const PORT = process.env.PORT || 3002;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
