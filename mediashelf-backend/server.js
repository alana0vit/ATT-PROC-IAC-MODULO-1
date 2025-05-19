require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const cors = require('cors');
const db = require('./db');

const app = express();
app.use(cors());
app.use(bodyParser.json());

const PORT = 3000;

// Rota de registro
app.post('/register', async (req, res) => {
  const { username, email, password, telefone } = req.body;
  const hashedPassword = await bcrypt.hash(password, 8);

  const sql = 'INSERT INTO users (username, email, password, telefone) VALUES (?, ?, ?, ?)';
  db.query(sql, [username, email, hashedPassword, telefone], (err, result) => {
    if (err) return res.status(500).send(err);
    res.send({ message: 'Usuário registrado com sucesso!', userId: result.insertId });
  });
});

// Rota de login
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  const sql = 'SELECT * FROM users WHERE email = ?';
  db.query(sql, [email], async (err, results) => {
    if (err) return res.status(500).send(err);
    if (results.length === 0) return res.status(404).send({ message: 'Usuário não encontrado' });

    const isMatch = await bcrypt.compare(password, results[0].password);
    if (!isMatch) return res.status(401).send({ message: 'Senha incorreta' });

    res.send({ message: 'Login bem-sucedido', user: results[0] });
  });
});

// Inicializa o servidor
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});