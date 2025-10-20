import React, { useState, useEffect } from 'react';
import { Lock, Send, Key, Users, MessageCircle, Eye, EyeOff, Shield, Download, Trash2 } from 'lucide-react';

// Configuration API - Modifier selon votre environnement
const API_BASE_URL = 'http://192.168.1.79:3000';

// ============================================
// UTILITAIRES CRYPTOGRAPHIQUES
// ============================================

/**
 * Génère une paire de clés RSA-OAEP 4096 bits
 */
async function generateRSAKeyPair() {
  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 4096,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256'
    },
    true, // extractable
    ['encrypt', 'decrypt']
  );
  return keyPair;
}

/**
 * Exporte une clé en format JWK (JSON Web Key)
 */
async function exportKey(key, type) {
  const exported = await window.crypto.subtle.exportKey('jwk', key);
  return JSON.stringify(exported);
}

/**
 * Importe une clé depuis JWK
 */
async function importPublicKey(jwkString) {
  const jwk = JSON.parse(jwkString);
  return await window.crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    true,
    ['encrypt']
  );
}

async function importPrivateKey(jwkString) {
  const jwk = JSON.parse(jwkString);
  return await window.crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    true,
    ['decrypt']
  );
}

/**
 * Génère une clé AES-GCM 256 bits
 */
async function generateAESKey() {
  return await window.crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

/**
 * Chiffre un message avec AES-GCM
 */
async function encryptWithAES(message, aesKey) {
  const encoder = new TextEncoder();
  const data = encoder.encode(message);
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  
  const encrypted = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    data
  );
  
  return {
    ciphertext: encrypted,
    iv
  };
}

/**
 * Déchiffre un message avec AES-GCM
 */
async function decryptWithAES(ciphertext, aesKey, iv) {
  const decrypted = await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    ciphertext
  );
  
  const decoder = new TextDecoder();
  return decoder.decode(decrypted);
}

/**
 * Chiffre la clé AES avec RSA-OAEP
 */
async function encryptAESKeyWithRSA(aesKey, rsaPublicKey) {
  const exported = await window.crypto.subtle.exportKey('raw', aesKey);
  const encrypted = await window.crypto.subtle.encrypt(
    { name: 'RSA-OAEP' },
    rsaPublicKey,
    exported
  );
  return encrypted;
}

/**
 * Déchiffre la clé AES avec RSA-OAEP
 */
async function decryptAESKeyWithRSA(encryptedKey, rsaPrivateKey) {
  const decrypted = await window.crypto.subtle.decrypt(
    { name: 'RSA-OAEP' },
    rsaPrivateKey,
    encryptedKey
  );
  
  return await window.crypto.subtle.importKey(
    'raw',
    decrypted,
    { name: 'AES-GCM', length: 256 },
    true,
    ['decrypt']
  );
}

// Conversion Array Buffer <-> Base64
function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

// ============================================
// COMPOSANT PRINCIPAL
// ============================================

export default function SecureChatApp() {
  const [view, setView] = useState('welcome'); // welcome, register, chat
  const [username, setUsername] = useState('');
  const [userId, setUserId] = useState(null);
  const [keyPair, setKeyPair] = useState(null);
  const [users, setUsers] = useState([]);
  const [selectedUser, setSelectedUser] = useState(null);
  const [messages, setMessages] = useState([]);
  const [messageText, setMessageText] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [decryptedMessages, setDecryptedMessages] = useState({});

  // Charger les utilisateurs
  useEffect(() => {
    if (view === 'chat') {
      loadUsers();
      loadMessages();
    }
  }, [view]);

  // Auto-refresh des messages toutes les 5 secondes
  useEffect(() => {
    if (view === 'chat' && userId) {
      const interval = setInterval(loadMessages, 5000);
      return () => clearInterval(interval);
    }
  }, [view, userId]);

  async function loadUsers() {
    try {
      const res = await fetch(`${API_BASE_URL}/users`);
      const data = await res.json();
      if (data.success) {
        setUsers(data.users.filter(u => u.id !== userId));
      }
    } catch (err) {
      console.error('Erreur chargement users:', err);
    }
  }

  async function loadMessages() {
    if (!userId) return;
    try {
      const res = await fetch(`${API_BASE_URL}/messages/${userId}`);
      const data = await res.json();
      if (data.success) {
        setMessages(data.messages);
      }
    } catch (err) {
      console.error('Erreur chargement messages:', err);
    }
  }

  // ============================================
  // INSCRIPTION
  // ============================================

  async function handleRegister() {
    if (!username.trim()) {
      setError('Veuillez entrer un nom d\'utilisateur');
      return;
    }

    setLoading(true);
    setError('');

    try {
      // 1. Génération des clés RSA
      const kp = await generateRSAKeyPair();
      const publicKeyJWK = await exportKey(kp.publicKey);

      // 2. Envoi au serveur
      const res = await fetch(`${API_BASE_URL}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: username.trim(),
          publicKey: publicKeyJWK
        })
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || 'Erreur d\'inscription');
      }

      // 3. Sauvegarde locale (dans cet exemple, en mémoire)
      setUserId(data.userId);
      setKeyPair(kp);
      setView('chat');

      // Sauvegarder dans sessionStorage pour persistance pendant la session
      sessionStorage.setItem('userId', data.userId);
      sessionStorage.setItem('username', username);
      sessionStorage.setItem('privateKey', await exportKey(kp.privateKey));
      sessionStorage.setItem('publicKey', publicKeyJWK);

    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  // ============================================
  // ENVOI DE MESSAGE
  // ============================================

  async function sendMessage() {
    if (!messageText.trim() || !selectedUser) return;

    setLoading(true);
    setError('');

    try {
      // 1. Récupérer la clé publique du destinataire
      const res = await fetch(`${API_BASE_URL}/users/${selectedUser.id}/publicKey`);
      const data = await res.json();
      
      if (!data.success) {
        throw new Error('Impossible de récupérer la clé publique');
      }

      const recipientPublicKey = await importPublicKey(data.publicKey);

      // 2. Générer clé AES
      const aesKey = await generateAESKey();

      // 3. Chiffrer le message avec AES
      const { ciphertext, iv } = await encryptWithAES(messageText, aesKey);

      // 4. Chiffrer la clé AES avec RSA
      const encryptedAESKey = await encryptAESKeyWithRSA(aesKey, recipientPublicKey);

      // 5. Envoyer au serveur
      const sendRes = await fetch(`${API_BASE_URL}/send`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          senderId: userId,
          receiverId: selectedUser.id,
          encryptedMessage: arrayBufferToBase64(ciphertext),
          encryptedKey: arrayBufferToBase64(encryptedAESKey),
          iv: arrayBufferToBase64(iv)
        })
      });

      const sendData = await sendRes.json();

      if (!sendData.success) {
        throw new Error('Erreur d\'envoi');
      }

      setMessageText('');
      alert('✅ Message envoyé et chiffré !');

    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  // ============================================
  // DÉCHIFFREMENT DE MESSAGE
  // ============================================

  async function decryptMessage(msg) {
    if (!keyPair) return;

    try {
      // 1. Déchiffrer la clé AES avec RSA
      const encryptedKey = base64ToArrayBuffer(msg.encrypted_key);
      const aesKey = await decryptAESKeyWithRSA(encryptedKey, keyPair.privateKey);

      // 2. Déchiffrer le message avec AES
      const ciphertext = base64ToArrayBuffer(msg.encrypted_message);
      const iv = base64ToArrayBuffer(msg.iv);
      const plaintext = await decryptWithAES(ciphertext, aesKey, iv);

      setDecryptedMessages(prev => ({
        ...prev,
        [msg.id]: plaintext
      }));

    } catch (err) {
      alert('❌ Erreur de déchiffrement : ' + err.message);
    }
  }

  // ============================================
  // RECHARGEMENT DEPUIS SESSION
  // ============================================

  useEffect(() => {
    const savedUserId = sessionStorage.getItem('userId');
    const savedUsername = sessionStorage.getItem('username');
    const savedPrivateKey = sessionStorage.getItem('privateKey');
    const savedPublicKey = sessionStorage.getItem('publicKey');

    if (savedUserId && savedPrivateKey && savedPublicKey) {
      (async () => {
        try {
          const privateKey = await importPrivateKey(savedPrivateKey);
          const publicKey = await importPublicKey(savedPublicKey);
          setUserId(parseInt(savedUserId));
          setUsername(savedUsername);
          setKeyPair({ privateKey, publicKey });
          setView('chat');
        } catch (err) {
          console.error('Erreur rechargement session:', err);
        }
      })();
    }
  }, []);

  // ============================================
  // DÉCONNEXION
  // ============================================

  function logout() {
    sessionStorage.clear();
    setView('welcome');
    setUserId(null);
    setKeyPair(null);
    setUsername('');
    setMessages([]);
    setDecryptedMessages({});
  }

  // ============================================
  // RENDU
  // ============================================

  if (view === 'welcome') {
    return (
      <div className="min-h-screen bg-gradient-to-br from-indigo-900 via-purple-900 to-pink-800 flex items-center justify-center p-4">
        <div className="bg-white rounded-2xl shadow-2xl p-8 max-w-md w-full">
          <div className="text-center mb-8">
            <Shield className="w-16 h-16 mx-auto text-indigo-600 mb-4" />
            <h1 className="text-3xl font-bold text-gray-800 mb-2">
              Messagerie E2EE
            </h1>
            <p className="text-gray-600">
              Chiffrement de bout en bout avec RSA-OAEP + AES-GCM
            </p>
          </div>

          <div className="space-y-4">
            <button
              onClick={() => setView('register')}
              className="w-full bg-indigo-600 hover:bg-indigo-700 text-white font-semibold py-3 rounded-lg transition duration-200 flex items-center justify-center gap-2"
            >
              <Key className="w-5 h-5" />
              Créer un compte
            </button>

            <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 text-sm text-blue-800">
              <strong>🔐 Sécurité garantie :</strong>
              <ul className="mt-2 space-y-1 ml-4 list-disc">
                <li>Clés RSA 4096 bits</li>
                <li>Chiffrement AES-GCM 256 bits</li>
                <li>Clés privées jamais transmises</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (view === 'register') {
    return (
      <div className="min-h-screen bg-gradient-to-br from-indigo-900 via-purple-900 to-pink-800 flex items-center justify-center p-4">
        <div className="bg-white rounded-2xl shadow-2xl p-8 max-w-md w-full">
          <h2 className="text-2xl font-bold text-gray-800 mb-6 text-center">
            Inscription
          </h2>

          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Nom d'utilisateur
              </label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                placeholder="alice_2025"
                disabled={loading}
              />
            </div>

            {error && (
              <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg text-sm">
                {error}
              </div>
            )}

            <button
              onClick={handleRegister}
              disabled={loading}
              className="w-full bg-indigo-600 hover:bg-indigo-700 disabled:bg-gray-400 text-white font-semibold py-3 rounded-lg transition duration-200"
            >
              {loading ? 'Génération des clés RSA...' : 'Créer mon compte'}
            </button>

            <button
              onClick={() => setView('welcome')}
              className="w-full text-gray-600 hover:text-gray-800 py-2"
            >
              ← Retour
            </button>
          </div>
        </div>
      </div>
    );
  }

  // Vue Chat
  return (
    <div className="min-h-screen bg-gray-100">
      {/* Header */}
      <div className="bg-indigo-600 text-white p-4 shadow-lg">
        <div className="max-w-6xl mx-auto flex justify-between items-center">
          <div className="flex items-center gap-3">
            <Lock className="w-6 h-6" />
            <div>
              <h1 className="text-xl font-bold">Messagerie Sécurisée</h1>
              <p className="text-sm text-indigo-200">Connecté : {username}</p>
            </div>
          </div>
          <button
            onClick={logout}
            className="bg-indigo-700 hover:bg-indigo-800 px-4 py-2 rounded-lg transition"
          >
            Déconnexion
          </button>
        </div>
      </div>

      <div className="max-w-6xl mx-auto p-4 grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Liste des utilisateurs */}
        <div className="bg-white rounded-lg shadow-md p-4">
          <div className="flex items-center gap-2 mb-4">
            <Users className="w-5 h-5 text-indigo-600" />
            <h2 className="text-lg font-semibold">Utilisateurs</h2>
          </div>

          <div className="space-y-2">
            {users.map(user => (
              <button
                key={user.id}
                onClick={() => setSelectedUser(user)}
                className={`w-full text-left p-3 rounded-lg transition ${
                  selectedUser?.id === user.id
                    ? 'bg-indigo-100 border-2 border-indigo-500'
                    : 'bg-gray-50 hover:bg-gray-100 border-2 border-transparent'
                }`}
              >
                <div className="font-medium text-gray-800">{user.username}</div>
                <div className="text-xs text-gray-500">ID: {user.id}</div>
              </button>
            ))}

            {users.length === 0 && (
              <p className="text-gray-500 text-sm text-center py-4">
                Aucun autre utilisateur
              </p>
            )}
          </div>

          <button
            onClick={loadUsers}
            className="w-full mt-4 bg-gray-200 hover:bg-gray-300 text-gray-700 py-2 rounded-lg text-sm transition"
          >
            🔄 Actualiser
          </button>
        </div>

        {/* Zone d'envoi et messages reçus */}
        <div className="md:col-span-2 space-y-4">
          {/* Envoi de message */}
          <div className="bg-white rounded-lg shadow-md p-4">
            <div className="flex items-center gap-2 mb-4">
              <Send className="w-5 h-5 text-indigo-600" />
              <h2 className="text-lg font-semibold">Envoyer un message</h2>
            </div>

            {selectedUser ? (
              <div className="space-y-3">
                <div className="bg-indigo-50 border border-indigo-200 p-3 rounded-lg">
                  <p className="text-sm text-indigo-800">
                    📧 Destinataire : <strong>{selectedUser.username}</strong>
                  </p>
                </div>

                <textarea
                  value={messageText}
                  onChange={(e) => setMessageText(e.target.value)}
                  placeholder="Tapez votre message confidentiel..."
                  className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 resize-none"
                  rows="4"
                  disabled={loading}
                />

                {error && (
                  <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg text-sm">
                    {error}
                  </div>
                )}

                <button
                  onClick={sendMessage}
                  disabled={loading || !messageText.trim()}
                  className="w-full bg-indigo-600 hover:bg-indigo-700 disabled:bg-gray-400 text-white font-semibold py-3 rounded-lg transition duration-200 flex items-center justify-center gap-2"
                >
                  <Lock className="w-5 h-5" />
                  {loading ? 'Chiffrement en cours...' : 'Chiffrer et envoyer'}
                </button>

                <div className="bg-green-50 border border-green-200 rounded-lg p-3 text-xs text-green-800">
                  <strong>🔒 Chiffrement hybride :</strong> Votre message sera chiffré avec AES-GCM, puis la clé AES sera chiffrée avec la clé publique RSA du destinataire.
                </div>
              </div>
            ) : (
              <div className="text-center py-8 text-gray-500">
                <Users className="w-12 h-12 mx-auto mb-2 text-gray-400" />
                <p>Sélectionnez un utilisateur pour envoyer un message</p>
              </div>
            )}
          </div>

          {/* Messages reçus */}
          <div className="bg-white rounded-lg shadow-md p-4">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <MessageCircle className="w-5 h-5 text-indigo-600" />
                <h2 className="text-lg font-semibold">Messages reçus</h2>
              </div>
              <button
                onClick={loadMessages}
                className="bg-gray-200 hover:bg-gray-300 text-gray-700 px-3 py-1 rounded text-sm transition"
              >
                🔄 Actualiser
              </button>
            </div>

            <div className="space-y-3 max-h-96 overflow-y-auto">
              {messages.map(msg => {
                const isDecrypted = decryptedMessages[msg.id];
                const date = new Date(msg.timestamp * 1000);

                return (
                  <div
                    key={msg.id}
                    className="border border-gray-200 rounded-lg p-4 hover:shadow-md transition"
                  >
                    <div className="flex items-start justify-between mb-2">
                      <div>
                        <p className="font-semibold text-gray-800">
                          De : {msg.sender_username}
                        </p>
                        <p className="text-xs text-gray-500">
                          {date.toLocaleString('fr-FR')}
                        </p>
                      </div>
                      <span className="bg-yellow-100 text-yellow-800 text-xs px-2 py-1 rounded">
                        🔒 Chiffré
                      </span>
                    </div>

                    {isDecrypted ? (
                      <div className="bg-green-50 border border-green-200 rounded p-3 mt-3">
                        <div className="flex items-start gap-2">
                          <Eye className="w-4 h-4 text-green-600 mt-1 flex-shrink-0" />
                          <p className="text-gray-800 flex-1">{isDecrypted}</p>
                        </div>
                      </div>
                    ) : (
                      <div className="mt-3">
                        <div className="bg-gray-100 rounded p-3 mb-2">
                          <p className="text-xs text-gray-600 font-mono break-all">
                            {msg.encrypted_message.substring(0, 100)}...
                          </p>
                        </div>
                        <button
                          onClick={() => decryptMessage(msg)}
                          className="w-full bg-indigo-600 hover:bg-indigo-700 text-white py-2 rounded-lg text-sm transition flex items-center justify-center gap-2"
                        >
                          <Key className="w-4 h-4" />
                          Déchiffrer ce message
                        </button>
                      </div>
                    )}
                  </div>
                );
              })}

              {messages.length === 0 && (
                <div className="text-center py-8 text-gray-500">
                  <MessageCircle className="w-12 h-12 mx-auto mb-2 text-gray-400" />
                  <p>Aucun message reçu</p>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}