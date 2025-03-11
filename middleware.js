const jwt = require("jsonwebtoken");
const User = require("./user"); 

const authMiddleware = async (req, res, next) => {
  const token = req.headers["authorization"];

  // Verifica se o token foi fornecido
  if (!token) {
    return res.status(403).json({ message: "Token não fornecido" });
  }

  // Remove o prefixo "Bearer " caso esteja presente
  const tokenWithoutBearer = token.replace("Bearer ", "");

  try {
    // Decodifica o token
    const decoded = jwt.verify(tokenWithoutBearer, process.env.JWT_SECRET);

    // Adiciona os dados do usuário no objeto `req` para usar nas rotas
    const user = await User.findById(decoded.userId);
    if (!user) {
      return res.status(404).json({ message: "Usuário não encontrado" });
    }

    // Armazenando dados do usuário na requisição para ser acessado nas rotas
    req.user = user;
    next(); // Passa para a próxima função ou rota
  } catch (err) {
    // Se houver erro ao verificar o token
    return res.status(401).json({ message: "Token inválido" });
  }
};

module.exports = authMiddleware;
