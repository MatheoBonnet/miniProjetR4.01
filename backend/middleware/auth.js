const jwt = require('jsonwebtoken');
const User = require('../models/User');

// Middleware pour vérifier le JWT
const authenticateToken = async (req, res, next) => {
  try {
    // Extraire le token du header Authorization
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Format: "Bearer TOKEN"

    if (!token) {
      return res.status(401).json({
        error: 'Access token requis',
        message: 'Vous devez être connecté pour accéder à cette ressource'
      });
    }

    // Vérifier et décoder le token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Récupérer l'utilisateur depuis MongoDB (sans le password)
    const user = await User.findById(decoded.userId).select('-password');

    if (!user) {
      return res.status(404).json({
        error: 'Utilisateur non trouvé',
        message: 'Ce compte n\'existe plus'
      });
    }

    // Ajouter l'utilisateur à la requête
    req.user = user;
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        error: 'Token expiré',
        message: 'Votre session a expiré, veuillez vous reconnecter'
      });
    }

    if (error.name === 'JsonWebTokenError') {
      return res.status(403).json({
        error: 'Token invalide',
        message: 'Le token fourni est invalide'
      });
    }

    res.status(500).json({
      error: 'Erreur serveur',
      message: error.message
    });
  }
};

module.exports = { authenticateToken };
