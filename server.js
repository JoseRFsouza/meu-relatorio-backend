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

app.post("/verify-token", (req, res) => {
  const token = req.headers.authorization?.split(" ")[1]; // Pega o token do header

  if (!token) {
    return res.status(401).json({ message: "Token não fornecido." });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    res.status(200).json({ message: "Token válido.", userId: decoded.userId });
  } catch (error) {
    res.status(401).json({ message: "Token inválido ou expirado." });
  }
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
      userType: 'Free',
    });

    await newUser.save();
    res.status(201).json({ message: "Usuário registrado com sucesso." });
  } catch (error) {
    console.error("Erro ao registrar usuário:", error);
    res.status(500).json({ message: "Erro ao registrar usuário." });
  }
});

// Rota para login e geração de token JWT
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

    // Retornar token e userType no login
    res.status(200).json({ token, userType: user.userType }); // Incluindo o userType na resposta
  } catch (error) {
    console.error("Erro ao fazer login:", error);
    res.status(500).json({ message: "Erro ao fazer login." });
  }
});


// Rota protegida, usando o middleware para autenticação
app.get("/profile", authenticateToken, async (req, res) => {
  try {
    // Aqui, o usuário já foi carregado e armazenado em `req.user` pelo middleware
    const user = req.user;

    // Retorna os dados do usuário
    res.json({
      message: "Acesso permitido",
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      phone: user.phone, // Caso tenha esse campo
      cityState: user.cityState, // Caso tenha esse campo
      userType: user.userType,
    });
  } catch (err) {
    console.error("Erro ao obter os dados do usuário:", err);
    return res.status(500).json({ message: "Erro ao obter dados do usuário" });
  }
});

// Rota protegida para editar dados do usuário
app.put("/profile/edit", authenticateToken, async (req, res) => {
  try {
    const { firstName, lastName, phone, cityState } = req.body;
    const userId = req.user._id; // ID do usuário autenticado

    if (!firstName || !lastName || !phone || !cityState) {
      return res.status(400).json({ message: "Todos os campos são obrigatórios." });
    }

    // Atualiza o usuário no banco de dados
    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { firstName, lastName, phone, cityState },
      { new: true }
    );

    if (!updatedUser) {
      return res.status(404).json({ message: "Usuário não encontrado." });
    }

    res.status(200).json({ message: "Dados atualizados com sucesso.", user: updatedUser });
  } catch (error) {
    console.error("Erro ao atualizar os dados do usuário:", error);
    res.status(500).json({ message: "Erro ao atualizar os dados do usuário." });
  }
});


const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));
