
const express = require('express');
const crypto = require('crypto');

const app = express();

app.use(express.json({
  limit: '100kb',
  verify: (req, res, buffer) => {
    req.rawBody = buffer.toString('utf8');
  }
}));

app.get('/', (req, res) => {
  res.send('Arena Evolution LIVE: servidor funcionando!');
});

app.get('/health', (req, res) => {
  res.json({ status: 'online' });
});

let cachedPublicKey = null;
let keyFetchedAt = 0;
const seenMessages = new Map();

async function getKickPublicKey() {
  if (cachedPublicKey && Date.now() - keyFetchedAt < 3600000) {
    return cachedPublicKey;
  }

  const response = await fetch(
    'https://api.kick.com/public/v1/public-key'
  );

  if (!response.ok) {
    throw new Error('Não foi possível obter a chave pública da Kick');
  }

  const text = await response.text();
  let key = text;

  if (text.trim().startsWith('{')) {
    const data = JSON.parse(text);
    key = data.public_key || data.data?.public_key;
  }

  if (typeof key !== 'string' || !key.includes('PUBLIC KEY')) {
    throw new Error('Formato de chave pública inesperado');
  }

  cachedPublicKey = key;
  keyFetchedAt = Date.now();

  return cachedPublicKey;
}

app.post('/webhook', async (req, res) => {
  try {
    const messageId = req.get('Kick-Event-Message-Id');
    const timestamp = req.get('Kick-Event-Message-Timestamp');
    const signature = req.get('Kick-Event-Signature');
    const eventType = req.get('Kick-Event-Type');

    if (!messageId || !timestamp || !signature || !req.rawBody) {
      return res.status(400).json({ error: 'Cabeçalhos ausentes' });
    }

    const sentAt = Date.parse(timestamp);

    if (!Number.isFinite(sentAt) || Math.abs(Date.now() - sentAt) > 5 * 60 * 1000) {
      return res.status(401).json({ error: 'Evento expirado ou timestamp inválido' });
    }

    if (seenMessages.has(messageId)) {
      return res.status(200).json({ received: true, duplicate: true });
    }

    const publicKey = await getKickPublicKey();
    const signedData = `${messageId}.${timestamp}.${req.rawBody}`;

    const valid = crypto.verify(
      'RSA-SHA256',
      Buffer.from(signedData),
      publicKey,
      Buffer.from(signature, 'base64')
    );

    if (!valid) {
      return res.status(401).json({ error: 'Assinatura inválida' });
    }

    seenMessages.set(messageId, Date.now());

    if (seenMessages.size > 2000) {
      const oldest = seenMessages.keys().next().value;
      seenMessages.delete(oldest);
    }

    console.log('Evento Kick verificado:', eventType);
    console.log('ID da mensagem:', messageId);

    if (eventType === 'chat.message.sent') {
      const message = req.body?.content || req.body?.message?.content;
      console.log('Mensagem de chat recebida:', message || '(sem texto)');
    }

    return res.status(200).json({ received: true });
  } catch (error) {
    console.error('Erro no webhook:', error.message);
    return res.status(500).json({ error: 'Erro interno' });
  }
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Arena Server rodando na porta ${PORT}`);
});
