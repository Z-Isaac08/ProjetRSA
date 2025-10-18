// server.js - Backend sécurisé pour messagerie chiffrée E2EE
const express = require('express');
const cors = require('cors');
const Database = require('better-sqlite3');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' })); // Pour les clés RSA volumineuses

// Initialisation de la base SQLite
const db = new Database('secure_chat.db');

// Création des tables si elles n'existent pas
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    public_key TEXT NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s', 'now'))
  );

  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL,
    receiver_id INTEGER NOT NULL,
    encrypted_message TEXT NOT NULL,
    encrypted_key TEXT NOT NULL,
    iv TEXT NOT NULL,
    timestamp INTEGER DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (sender_id) REFERENCES users(id),
    FOREIGN KEY (receiver_id) REFERENCES users(id)
  );

  CREATE INDEX IF NOT EXISTS idx_messages_receiver 
  ON messages(receiver_id, timestamp DESC);
`);

console.log('✅ Base de données initialisée');

// ============================================
// ENDPOINTS API
// ============================================

/**
 * POST /register
 * Enregistre un nouvel utilisateur avec sa clé publique RSA
 * Body: { username: string, publicKey: string }
 */
app.post('/register', (req, res) => {
  try {
    const { username, publicKey } = req.body;

    if (!username || !publicKey) {
      return res.status(400).json({ 
        error: 'Username et publicKey requis' 
      });
    }

    // Validation basique
    if (username.length < 3 || username.length > 50) {
      return res.status(400).json({ 
        error: 'Username doit contenir entre 3 et 50 caractères' 
      });
    }

    const stmt = db.prepare(
      'INSERT INTO users (username, public_key) VALUES (?, ?)'
    );
    
    const result = stmt.run(username, publicKey);

    res.status(201).json({
      success: true,
      userId: result.lastInsertRowid,
      username
    });

  } catch (error) {
    if (error.message.includes('UNIQUE')) {
      return res.status(409).json({ 
        error: 'Ce nom d\'utilisateur existe déjà' 
      });
    }
    console.error('Erreur registration:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

/**
 * GET /users
 * Retourne la liste de tous les utilisateurs (sans clés privées)
 */
app.get('/users', (req, res) => {
  try {
    const stmt = db.prepare(
      'SELECT id, username, created_at FROM users ORDER BY username'
    );
    const users = stmt.all();

    res.json({ 
      success: true, 
      users 
    });
  } catch (error) {
    console.error('Erreur liste users:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

/**
 * GET /users/:id/publicKey
 * Récupère la clé publique RSA d'un utilisateur spécifique
 */
app.get('/users/:id/publicKey', (req, res) => {
  try {
    const userId = parseInt(req.params.id, 10);

    if (isNaN(userId)) {
      return res.status(400).json({ error: 'ID invalide' });
    }

    const stmt = db.prepare(
      'SELECT username, public_key FROM users WHERE id = ?'
    );
    const user = stmt.get(userId);

    if (!user) {
      return res.status(404).json({ 
        error: 'Utilisateur introuvable' 
      });
    }

    res.json({
      success: true,
      username: user.username,
      publicKey: user.public_key
    });

  } catch (error) {
    console.error('Erreur récupération clé publique:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

/**
 * POST /send
 * Stocke un message chiffré
 * Body: {
 *   senderId: number,
 *   receiverId: number,
 *   encryptedMessage: string,
 *   encryptedKey: string,
 *   iv: string
 * }
 */
app.post('/send', (req, res) => {
  try {
    const { 
      senderId, 
      receiverId, 
      encryptedMessage, 
      encryptedKey, 
      iv 
    } = req.body;

    // Validation
    if (!senderId || !receiverId || !encryptedMessage || 
        !encryptedKey || !iv) {
      return res.status(400).json({ 
        error: 'Tous les champs sont requis' 
      });
    }

    // Vérifier que les utilisateurs existent
    const checkUsers = db.prepare(
      'SELECT COUNT(*) as count FROM users WHERE id IN (?, ?)'
    );
    const { count } = checkUsers.get(senderId, receiverId);

    if (count !== 2) {
      return res.status(404).json({ 
        error: 'Expéditeur ou destinataire introuvable' 
      });
    }

    const stmt = db.prepare(`
      INSERT INTO messages 
      (sender_id, receiver_id, encrypted_message, encrypted_key, iv)
      VALUES (?, ?, ?, ?, ?)
    `);

    const result = stmt.run(
      senderId, 
      receiverId, 
      encryptedMessage, 
      encryptedKey, 
      iv
    );

    res.status(201).json({
      success: true,
      messageId: result.lastInsertRowid
    });

  } catch (error) {
    console.error('Erreur envoi message:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

/**
 * GET /messages/:userId
 * Récupère tous les messages reçus par un utilisateur
 */
app.get('/messages/:userId', (req, res) => {
  try {
    const userId = parseInt(req.params.userId, 10);

    if (isNaN(userId)) {
      return res.status(400).json({ error: 'ID invalide' });
    }

    const stmt = db.prepare(`
      SELECT 
        m.id,
        m.sender_id,
        u.username as sender_username,
        m.encrypted_message,
        m.encrypted_key,
        m.iv,
        m.timestamp
      FROM messages m
      JOIN users u ON m.sender_id = u.id
      WHERE m.receiver_id = ?
      ORDER BY m.timestamp DESC
    `);

    const messages = stmt.all(userId);

    res.json({
      success: true,
      messages
    });

  } catch (error) {
    console.error('Erreur récupération messages:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

/**
 * GET /health
 * Endpoint de santé pour vérifier que le serveur fonctionne
 */
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: Date.now() 
  });
});

// Gestion des erreurs 404
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint introuvable' });
});

// Démarrage du serveur
app.listen(PORT, '0.0.0.0', () => {
  console.log(`
    🔐 Serveur de messagerie sécurisée E2EE 
    📡 Port: ${PORT}
    🌐 Accessible sur: http://0.0.0.0:${PORT}`
  );
});

// Fermeture propre de la DB
process.on('SIGINT', () => {
  db.close();
  console.log('\n✅ Base de données fermée proprement');
  process.exit(0);
});