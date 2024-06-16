require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const path = require('path');

const app = express();
const PORT = process.env.SERVER_PORT || 3000;

const pool = new Pool({
    user: process.env.USER_DATA_BASE, // Имя пользователя с необходимыми правами
    host: process.env.DATA_BASE_HOST,
    database: process.env.DATA_BASE,
    password: process.env.DATA_BASE_PASSWORD,
    port: process.env.DATA_BASE_PORT,
});

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Регистрация пользователя
app.post('/register', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Хеширование пароля перед сохранением в базу данных
        const hashedPassword = await bcrypt.hash(password, 10);

        // Вставка пользователя в базу данных PostgreSQL
        const query = 'INSERT INTO users (username, password) VALUES ($1, $2)';
        const values = [username, hashedPassword];

        await pool.query(query, values);

        res.status(201).redirect('/login.html');
    } catch (error) {
        console.error(error);
        res.status(500).send("Error registering user");
    }
});

// Авторизация пользователя
app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        const query = 'SELECT * FROM users WHERE username = $1';
        const result = await pool.query(query, [username]);

        if (result.rows.length === 0) {
            return res.status(404).send('User not found');
        }

        const user = result.rows[0];

        // Проверка пароля
        const passwordMatch = await bcrypt.compare(password, user.password);

        if (passwordMatch) {
            // Генерация JWT токена для авторизации
            const token = jwt.sign({ username }, 'secretKey', { expiresIn: '1h' });
            res.status(200).json({ token });
        } else {
            res.status(401).send("Authentication failed");
        }
    } catch (error) {
        console.error(error);
        res.status(500).send("Error authenticating user");
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
