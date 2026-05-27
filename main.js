const express = require('express');
const session = require('express-session');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');

const app = express();
const PORT = 6900;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 } // 24 часа
}));
app.use(express.static(path.join(__dirname)));

const db = new sqlite3.Database('./database.db');

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      login TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      Fname TEXT NOT NULL,
      date DATE NOT NULL,
      number INTEGER NOT NULL,
      email TEXT NOT NULL
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS requests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      status TEXT DEFAULT 'new'
    )
  `);
});

async function registerUser(login, password, Fname, date, number, email) {
  const hash = await bcrypt.hash(password, 10);

  return new Promise((resolve, reject) => {
    db.run(
      'INSERT INTO users (login, password, Fname, date, number, email) VALUES (?, ?, ?, ?, ?, ?)',
      [login, hash, Fname, date, number, email],
      function (err) {
        if (err) reject(err);
        else resolve({ id: this.lastID, login });
      }
    );
  });
}

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.post('/api/login', (req, res) => {
  const { login, password } = req.body;

  if (!login || !password) {
    return res.status(400).json({ error: 'Логин и пароль обязательны' });
  }

  db.get('SELECT * FROM users WHERE login = ?', [login], async (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Ошибка базы данных' });
    }
    if (!user) {
      return res.status(401).json({ error: 'Пользователь не найден' });
    }

    try {
      const isValid = await bcrypt.compare(password, user.password);
      if (isValid) {
        req.session.userId = user.id;
        req.session.userLogin = user.login;
        res.json({ success: true, user: { id: user.id, login: user.login } });
      } else {
        res.status(401).json({ error: 'Неверный пароль' });
      }
    } catch (error) {
      res.status(500).json({ error: 'Ошибка сервера' });
    }
  });
});

app.post('/api/register', async (req, res) => {
  try {
    const { login, password, Fname, date, number, email } = req.body;

    if (!login || !password || !Fname || !date || !number || !email) {
      return res.status(400).json({ error: 'Все поля обязательны для заполнения' });
    }

    const user = await registerUser(login, password, Fname, date, number, email);
    res.json({ success: true, user });
  } catch (error) {
    if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      res.status(409).json({ error: 'Пользователь с таким логином уже существует' });
    } else {
      res.status(500).json({ error: 'Ошибка сервера' });
    }
  }
});

app.get('/api/requests', (req, res) => {
  db.all('SELECT * FROM requests ORDER BY id DESC', [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'ошибка' });
    res.json(rows);
  });
});

app.patch('/api/requests/:id/status', (req, res) => {
  const { id } = req.params;
  const { status } = req.body;

  if (!status) {
    return res.status(400).json({ error: 'Статус обязателен для обновления' });
  }

  db.run(
    'UPDATE requests SET status = ? WHERE id = ?',
    [status, id],
    function (err) {
      if (err) return res.status(500).json({ error: 'ошибка' });
      if (this.changes === 0) return res.status(404).json({ error: 'Not found' });
      res.json({ success: true });
    }
  );
});

app.get('/api/requests', (req, res) => {
  db.all('SELECT * FROM requests ORDER BY id DESC', [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'ошибка' });
    res.json(rows);
  });
});

app.patch('/api/requests/:id/status', (req, res) => {
  const { id } = req.params;
  const { status } = req.body;

  db.run(
    'UPDATE requests SET status = ? WHERE id = ?',
    [status, id],
    function (err) {
      if (err) return res.status(500).json({ error: 'ошибка' });
      if (this.changes === 0) return res.status(404).json({ error: 'Not found' });
      res.json({ success: true });
    }
  );
});

app.listen(PORT, () => {
  console.log(`Server started: http://localhost:${PORT}`);
});
