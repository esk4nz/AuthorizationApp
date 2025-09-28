require("dotenv").config();
const path = require("path");
const express = require("express");
const cors = require("cors");
const morgan = require("morgan");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { supabase } = require("./db");
const { authRequired, requireRole } = require("./middleware/auth");

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());
app.use(morgan("dev"));

const USERNAME_MIN = 3;
const USERNAME_MAX = 32;
const PASSWORD_MIN = 8;
const PASSWORD_MAX = 32;

function validUsername(username) {
  return typeof username === "string" && username.length >= USERNAME_MIN && username.length <= USERNAME_MAX;
}
function validPassword(password) {
  return typeof password === "string" && password.length >= PASSWORD_MIN && password.length <= PASSWORD_MAX;
}

app.get("/health", (_req, res) => res.json({ ok: true }));

// Реєстрація
app.post("/users/register", async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!validUsername(username) || !validPassword(password)) {
      return res.status(400).json({
        error: `Invalid username or password. username: ${USERNAME_MIN}-${USERNAME_MAX}, password: ${PASSWORD_MIN}-${PASSWORD_MAX}`
      });
    }

    const existing = await supabase
      .from("users")
      .select("id")
      .eq("username", username)
      .maybeSingle();

    if (existing.data) {
      return res.status(409).json({ error: "Username is already taken" });
    }

    const password_hash = await bcrypt.hash(password, 10);
    const insert = await supabase
      .from("users")
      .insert({ username, password_hash, role: "user" })
      .select("id, username, role, created_at")
      .single();

    if (insert.error) throw insert.error;

    res.status(201).json({ user: insert.data });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Registration failed" });
  }
});

// Логін -> JWT
app.post("/users/login", async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (typeof username !== "string" || typeof password !== "string") {
      return res.status(400).json({ error: "username and password are required" });
    }

    const q = await supabase
      .from("users")
      .select("id, username, password_hash, role")
      .eq("username", username)
      .single();

    if (q.error || !q.data) return res.status(401).json({ error: "Invalid credentials" });

    const ok = await bcrypt.compare(password, q.data.password_hash);
    if (!ok) return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign(
      { sub: q.data.id, username: q.data.username, role: q.data.role },
      process.env.JWT_SECRET,
      { algorithm: "HS256", expiresIn: "2h" }
    );

    res.json({
      token,
      user: { id: q.data.id, username: q.data.username, role: q.data.role }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Login failed" });
  }
});

// Поточний користувач
app.get("/me", authRequired, async (req, res) => {
  try {
    const { sub } = req.user;
    const q = await supabase
      .from("users")
      .select("id, username, role, created_at")
      .eq("id", sub)
      .single();

    if (q.error || !q.data) return res.status(404).json({ error: "User not found" });
    res.json({ me: q.data });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to load profile" });
  }
});

// Оновлення користувача (owner або admin)
app.put("/users/:id", authRequired, async (req, res) => {
  try {
    const idNum = Number(req.params.id);
    if (!Number.isFinite(idNum)) return res.status(400).json({ error: "Invalid user id" });

    const isOwner = Number(req.user.sub) === idNum;
    const isAdmin = req.user.role === "admin";
    if (!isOwner && !isAdmin) return res.status(403).json({ error: "Forbidden" });

    const updates = {};
    const { username, password, role } = req.body || {};

    if (typeof username === "string" && username.trim()) {
      const u = username.trim();
      if (!validUsername(u)) return res.status(400).json({ error: `Username must be ${USERNAME_MIN}-${USERNAME_MAX} chars` });
      updates.username = u;
    }
    if (typeof password === "string" && password) {
      if (!validPassword(password)) return res.status(400).json({ error: `Password must be ${PASSWORD_MIN}-${PASSWORD_MAX} chars` });
      updates.password_hash = await bcrypt.hash(password, 10);
    }
    if (isAdmin && (role === "user" || role === "admin")) {
      updates.role = role;
    }

    if (Object.keys(updates).length === 0) return res.status(400).json({ error: "No valid fields to update" });

    const q = await supabase
      .from("users")
      .update(updates)
      .eq("id", idNum)
      .select("id, username, role, created_at")
      .single();

    if (q.error) {
      if (q.error.code === "23505") return res.status(409).json({ error: "Username already exists" });
      throw q.error;
    }

    res.json({ user: q.data });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Update failed" });
  }
});

// Лише для адміна
app.get("/admin/users", authRequired, requireRole("admin"), async (_req, res) => {
  try {
    const q = await supabase
      .from("users")
      .select("id, username, role, created_at")
      .order("created_at", { ascending: true });

    if (q.error) throw q.error;

    res.json({ users: q.data });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to list users" });
  }
});

// Віддаємо фронтенд
const webDir = path.resolve(__dirname, "../../web");
app.use(express.static(webDir));
app.get("*", (_req, res) => {
  res.sendFile(path.join(webDir, "index.html"));
});

app.listen(PORT, () => {
  console.log(`API listening on http://localhost:${PORT}`);
});