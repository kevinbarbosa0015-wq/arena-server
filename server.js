
const express = require('express');
const crypto = require('crypto');

const app = express();
app.use(express.json({
  limit: '100kb',
  verify: (req, res, buffer) => {
    req.rawBody = buffer.toString('utf8');
  }
}));

const CLIENT_ID = process.env.KICK_CLIENT_ID;
const CLIENT_SECRET = process.env.KICK_CLIENT_SECRET;
const REDIRECT_URI = 'https://arena-server-2.onrender.com/auth/callback';

const pending = new Map();
let accessToken = null;
let refreshToken = null;
let publicKey = null;
const seenMessages = new Set();

app.get('/', (req, res) => {
  res.send('Arena Evolution LIVE: servidor funcionando!');
});

app.get('/health', (req, res) => {
  res.json({ status: 'online' });
});

app.get('/auth', (req, res) => {
  if (!CLIENT_ID || !CLIENT_SECRET) {
    return res.status(500).send('Configure as variáveis da Kick no Render.');
  }

  const state = crypto.randomBytes(24).toString('hex');
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256')
    .update(verifier).digest('base64url');

  pending.set(state, {
    verifier,
    created: Date.now()
  });

  const url = new URL('https://id.kick.com/oauth/authorize');
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', CLIENT_ID);
  url.searchParams.set('redirect_uri', REDIRECT_URI);
  url.searchParams.set('scope', 'user:read events:subscribe');
  url.searchParams.set('state', state);
  url.searchParams.set('code_challenge', challenge);
  url.searchParams.set('code_challenge_method', 'S256');

  res.redirect(url.toString());
});

app.get('/auth/callback', async (req, res) => {
  try {
    const { code, state, error } = req.query;
    if (error) return res.status(400).send('Autorização recusada pela Kick.');
    const data = pending.get(state);
    if (!code || !data || Date.now() - data.created > 600000) {
      return res.status(400).send('Autorização inválida ou expirada. Tente novamente em /auth.');
    }
    pending.delete(state);

    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      redirect_uri: REDIRECT_URI,
      code: String(code),
      code_verifier: data.verifier
    });

    const response = await fetch('https://id.kick.com/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body
    });

    const result = await response.json();
    if (!response.ok || !result.access_token) {
      console.error('Falha OAuth:', response.status, result.error);
      return res.status(400).send('Não foi possível autorizar. Confira as configurações da Kick e tente novamente.');
    }

    accessToken = result.access_token;
    refreshToken = result.refresh_token || null;

    const userResponse = await fetch('https://api.kick.com/public/v1/users', {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    const userData = await userResponse.json();

    const user = userData.data?.[0];
    if (!user?.user_id) {
      return res.status(500).send('Autorizado, mas não consegui identificar o usuário da Kick.');
    }

    const subResponse = await fetch(
      'https://api.kick.com/public/v1/events/subscriptions',
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          broadcaster_user_id: user.user_id,
          events: [{ name: 'chat.message.sent', version: 1 }],
          method: 'webhook'
        })
      }
    );

    const subResult = await subResponse.text();
    console.log('Inscrição chat:', subResponse.status, subResult);

    if (!subResponse.ok) {
      return res.status(502).send('Conta autorizada, mas a inscrição no chat falhou. Veja os logs do Render.');
    }

    res.send('Kick autorizada e inscrição no chat solicitada! Agora confira os logs do Render.');
  } catch (err) {
    console.error('Erro OAuth:', err.message);
    res.status(500).send('Erro interno durante a autorização.');
  }
});

async function getPublicKey() {
  if (!publicKey) {
    const response = await fetch('https://api.kick.com/public/v1/public-key');
    if (!response.ok) throw new Error('Falha ao obter chave pública da Kick');
    publicKey = await response.text();
    if (publicKey.trim().startsWith('{')) {
      const obj = JSON.parse(publicKey);
      publicKey = obj.public_key || obj.data?.public_key;
    }
  }
  return publicKey;
}

app.post('/webhook', async (req, res) => {
  try {
    const id = req.get('Kick-Event-Message-Id');
    const timestamp = req.get('Kick-Event-Message-Timestamp');
    const signature = req.get('Kick-Event-Signature');
    const type = req.get('Kick-Event-Type');

    if (!id || !timestamp || !signature || !req.rawBody) {
      return res.status(400).json({ error: 'Cabeçalhos ausentes' });
    }

    if (Math.abs(Date.now() - Date.parse(timestamp)) > 300000) {
      return res.status(401).json({ error: 'Evento expirado' });
    }

    if (seenMessages.has(id)) {
      return res.status(200).json({ received: true, duplicate: true });
    }

    const key = await getPublicKey();
    const valid = crypto.verify(
      'RSA-SHA256',
      Buffer.from(`${id}.${timestamp}.${req.rawBody}`),
      key,
      Buffer.from(signature, 'base64')
    );

    if (!valid) return res.status(401).json({ error: 'Assinatura inválida' });

    seenMessages.add(id);
    if (seenMessages.size > 2000) {
      seenMessages.clear();
    }

    if (type === 'chat.message.sent') {
      const event = req.body;
      const content = event.content || event.message?.content || '';
      const username = event.sender?.username || 'usuário';
      console.log('CHAT:', username, content);
    }

    res.status(200).json({ received: true });
  } catch (err) {
    console.error('Erro webhook:', err.message);
    res.status(500).json({ error: 'Erro interno' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Arena Server rodando na porta ${PORT}`);
});
