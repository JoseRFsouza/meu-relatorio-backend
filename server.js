require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const User = require("./user"); 
const authenticateToken = require("./middleware"); // Importando o middleware de autenticação

const app = express();
app.use(cors());
app.use(express.json());

mongoose.connect(process.env.MONGO_URI, { 
  useNewUrlParser: true, 
  useUnifiedTopology: true 
}).then(() => console.log("Conectado ao MongoDB"))
  .catch(err => console.error("Erro ao conectar ao MongoDB:", err));

  // 📝 Rota protegida /editor
app.get("/editor", authenticateToken, (req, res) => {
  res.json({ message: "Acesso ao Editor permitido", userId: req.user.userId });
});

// 📝 Rota protegida /csvUploader
app.get("/csvUploader", authenticateToken, (req, res) => {
  res.json({ message: "Acesso ao CSV Uploader permitido", userId: req.user.userId });
});

// 📝 Rota para cadastrar usuário
app.post("/register", async (req, res) => {
  const { firstName, lastName, phone, cityState, email, password } = req.body;

  if (!firstName || !lastName || !phone || !cityState || !email || !password) {
    return res.status(400).json({ message: "Todos os campos são obrigatórios." });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      firstName,
      lastName,
      phone,
      cityState,
      email,
      password: hashedPassword,
    });

    await newUser.save();
    res.status(201).json({ message: "Usuário registrado com sucesso." });
  } catch (error) {
    console.error("Erro ao registrar usuário:", error);
    res.status(500).json({ message: "Erro ao registrar usuário." });
  }
});

// 📝 Rota para login e geração de token JWT
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "E-mail e senha são obrigatórios." });
  }

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(400).json({ message: "Usuário não encontrado." });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(400).json({ message: "Senha incorreta." });
    }

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });

    res.status(200).json({ token });
  } catch (error) {
    console.error("Erro ao fazer login:", error);
    res.status(500).json({ message: "Erro ao fazer login." });
  }
});

// 📝 Rota protegida (verifica JWT)
app.get("/profile", (req, res) => {
  const token = req.headers["authorization"];
  if (!token) return res.status(403).json({ message: "Token não fornecido" });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ message: "Token inválido" });
    res.json({ message: "Acesso permitido", userId: decoded.userId });
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));
