const jwt = require("jsonwebtoken");

// Middleware para validar o token JWT
const authenticateToken = (req, res, next) => {
  const token = req.headers["authorization"]; // Obtemos o token do cabeçalho

  if (!token) {
    return res.status(403).json({ message: "Token não fornecido" });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: "Token inválido" });
    }
    req.user = decoded; // Armazenamos os dados do usuário decodificados para uso posterior
    next(); // Chama o próximo middleware ou a rota
  });
};

module.exports = authenticateToken;
