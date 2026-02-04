const { ObjectId } = require('mongodb');
const bcrypt = require('bcryptjs');

// ============================================
// Fonctions Helper pour les utilisateurs
// ============================================

// Trouver un utilisateur par email
async function findUserByEmail(db, email) {
  return await db.collection('users').findOne({ email: email.toLowerCase() });
}

// Trouver un utilisateur par ID
async function findUserById(db, userId) {
  return await db.collection('users').findOne({ _id: new ObjectId(userId) });
}

// Créer un utilisateur (inscription classique email/password)
async function createUser(db, { email, password, name }) {
  // Hash du mot de passe
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);

  const result = await db.collection('users').insertOne({
    email: email.toLowerCase(),
    password: hashedPassword,
    name,
    provider: 'local',
    createdAt: new Date()
  });

  return {
    _id: result.insertedId,
    email: email.toLowerCase(),
    name,
    provider: 'local',
    createdAt: new Date()
  };
}

// Comparer le mot de passe
async function comparePassword(plainPassword, hashedPassword) {
  return await bcrypt.compare(plainPassword, hashedPassword);
}

// ============================================
// Fonctions Helper pour Google OAuth
// ============================================

// Trouver un utilisateur par son Google ID
async function findUserByGoogleId(db, googleId) {
  return await db.collection('users').findOne({ googleId });
}

// Créer un utilisateur depuis Google OAuth
async function createUserFromGoogle(db, { googleId, email, name, picture }) {
  const result = await db.collection('users').insertOne({
    googleId,
    email: email ? email.toLowerCase() : null,
    name,
    picture,
    provider: 'google',
    createdAt: new Date()
    // Pas de champ password pour les utilisateurs OAuth
  });

  return {
    _id: result.insertedId,
    googleId,
    email: email ? email.toLowerCase() : null,
    name,
    picture,
    provider: 'google',
    createdAt: new Date()
  };
}

module.exports = {
  findUserByEmail,
  findUserById,
  createUser,
  comparePassword,
  findUserByGoogleId,
  createUserFromGoogle
};
