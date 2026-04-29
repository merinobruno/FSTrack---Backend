require('dotenv').config();

const express = require('express');
const cors = require('cors');

const authRoutes = require('./auth');
const adminRoutes = require('./admin');

const app = express();

app.use(cors());
app.use(express.json());

app.use('/auth', authRoutes);
app.use('/admin', adminRoutes);

app.get('/', (_req, res) => {
  res.redirect('/admin');
});

app.get('/health', (_req, res) => {
  res.json({ ok: true });
});

const port = process.env.PORT || 3001;

app.listen(port, () => {
  console.log(`API listening on port ${port}`);
});