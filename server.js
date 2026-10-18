const express = require('express');
const app = express();

app.use(express.json());

app.get('/', (req, res) => {
  res.send('Arena Evolution LIVE: servidor funcionando!');
});

app.get('/health', (req, res) => {
  res.json({ status: 'online' });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Arena Server rodando na porta ${PORT}`);
});
