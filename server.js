require("dotenv").config();
const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());
app.use(express.json());

mongoose.connect(process.env.MONGO_URI);

const UserSchema = new mongoose.Schema({
  email: String,
  password: String,
});

const User = mongoose.model("User", UserSchema);

// 📝 Rota para cadastrar usuário
app.post("/register", async (req, res) => {
  const { email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const user = new User({ email, password: hashedPassword });
  await user.save();
  res.json({ message: "Usuário cadastrado!" });
});

// 📝 Rota para login e geração de token JWT
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ message: "Usuário não encontrado" });

  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) return res.status(400).json({ message: "Senha incorreta" });

  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "30d" });
  res.json({ token });
});

// 📝 Rota protegida (verifica JWT)
app.get("/profile", (req, res) => {
  const token = req.headers["authorization"];
  if (!token) return res.status(403).json({ message: "Token não fornecido" });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ message: "Token inválido" });
    res.json({ message: "Acesso permitido", userId: decoded.id });
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));
