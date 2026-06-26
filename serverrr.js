const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const CryptoJS = require('crypto-js');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator'); // ✅ Добавляем валидацию
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex'); // ✅ Генерируем надёжный ключ

// ============ БЕЗОПАСНОСТЬ ============
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:"],
            connectSrc: ["'self'"]
        }
    }
}));

// ✅ Защита от CSRF
const csrf = require('csurf');
const csrfProtection = csrf({ cookie: true });
app.use(csrfProtection);

// ✅ Более строгий rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
});
app.use('/api/', limiter);

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 3, // ✅ Уменьшаем до 3 попыток
});
app.use('/api/login', authLimiter);
app.use('/api/register', authLimiter);

app.use(express.json({ limit: '1mb' })); // ✅ Ограничиваем размер
app.use(express.static('public', { maxAge: '1d' }));
app.use(cookieParser());

// ============ БАЗА ДАННЫХ С ШИФРОВАНИЕМ ============
// ✅ Функция для шифрования чувствительных данных
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');

function encryptSecret(text, password) {
    // Используем комбинацию пароля и ключа
    const combinedKey = CryptoJS.PBKDF2(password, ENCRYPTION_KEY, { keySize: 256/32, iterations: 10000 });
    return CryptoJS.AES.encrypt(text, combinedKey.toString()).toString();
}

function decryptSecret(encrypted, password) {
    const combinedKey = CryptoJS.PBKDF2(password, ENCRYPTION_KEY, { keySize: 256/32, iterations: 10000 });
    const decrypted = CryptoJS.AES.decrypt(encrypted, combinedKey.toString());
    return decrypted.toString(CryptoJS.enc.Utf8);
}

// ============ БЕЗОПАСНЫЕ SQL-ЗАПРОСЫ ============
// ✅ Всегда используем параметризованные запросы!
function safeQuery(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.get(sql, params, (err, row) => {
            if (err) reject(err);
            else resolve(row);
        });
    });
}

function safeAll(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.all(sql, params, (err, rows) => {
            if (err) reject(err);
            else resolve(rows);
        });
    });
}

function safeRun(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.run(sql, params, function(err) {
            if (err) reject(err);
            else resolve(this);
        });
    });
}

// ============ АУТЕНТИФИКАЦИЯ ============
const auth = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.userId = decoded.userId;
        req.isAdmin = decoded.isAdmin;
        next();
    } catch (err) {
        res.status(401).json({ error: 'Invalid token' });
    }
};

// ✅ Проверка прав администратора
const adminOnly = (req, res, next) => {
    if (!req.isAdmin) {
        return res.status(403).json({ error: 'Forbidden' });
    }
    next();
};

// ============ API ============
app.post('/api/register', [
    body('globalKey').isString().notEmpty(),
    body('username').isLength({ min: 3, max: 30 }).matches(/^[a-zA-Z0-9_]+$/),
    body('password').isLength({ min: 8 }) // ✅ Минимум 8 символов
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ error: errors.array()[0].msg });
    }

    const { globalKey, username, password } = req.body;
    
    // ✅ Используем constant-time сравнение
    if (!crypto.timingSafeEqual(Buffer.from(globalKey), Buffer.from('silence'))) {
        return res.status(403).json({ error: 'Invalid key' });
    }

    try {
        const salt = await bcrypt.genSalt(12); // ✅ 12 раундов
        const hash = await bcrypt.hash(password, salt);
        
        const result = await safeRun(
            'INSERT INTO users (username, password) VALUES (?, ?)',
            [username, hash]
        );
        
        const token = jwt.sign(
            { userId: result.lastID, isAdmin: 0 },
            JWT_SECRET,
            { expiresIn: '1d' } // ✅ Уменьшаем время жизни
        );
        
        res.cookie('token', token, {
            httpOnly: true,
            secure: true, // ✅ Всегда true в продакшене
            sameSite: 'strict',
            maxAge: 24 * 60 * 60 * 1000,
            domain: process.env.COOKIE_DOMAIN || undefined
        });
        
        res.json({ success: true, username, isAdmin: false });
    } catch(e) {
        // ✅ Не выводим детали ошибки
        if (e.message.includes('UNIQUE')) {
            res.status(400).json({ error: 'Username already exists' });
        } else {
            res.status(500).json({ error: 'Registration failed' });
        }
    }
});

app.post('/api/login', [
    body('globalKey').isString().notEmpty(),
    body('username').isString().notEmpty(),
    body('password').isString().notEmpty()
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ error: 'Invalid input' });
    }

    const { globalKey, username, password } = req.body;
    
    if (!crypto.timingSafeEqual(Buffer.from(globalKey), Buffer.from('silence'))) {
        return res.status(403).json({ error: 'Invalid key' });
    }

    try {
        const user = await safeQuery(
            'SELECT * FROM users WHERE username = ?',
            [username]
        );
        
        if (!user) {
            // ✅ Имитируем задержку для защиты от timing attacks
            await bcrypt.hash('dummy', 12);
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) {
            await bcrypt.hash('dummy', 12);
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign(
            { userId: user.id, isAdmin: user.isAdmin },
            JWT_SECRET,
            { expiresIn: '1d' }
        );
        
        res.cookie('token', token, {
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
            maxAge: 24 * 60 * 60 * 1000,
            domain: process.env.COOKIE_DOMAIN || undefined
        });
        
        res.json({ success: true, username, isAdmin: user.isAdmin === 1 });
    } catch(e) {
        res.status(500).json({ error: 'Login failed' });
    }
});

// ✅ POSTS с безопасной обработкой
app.post('/api/posts', [
    auth,
    upload.single('file'),
    body('content').isString().isLength({ max: 5000 }),
    body('title').optional().isString().isLength({ max: 200 }),
    body('is_secret').optional().isBoolean()
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ error: 'Invalid input' });
    }

    const { title, content, hashtags, folderId, is_secret, secret_password } = req.body;
    
    let media = null;
    let filePath = null;
    let encryptedSecret = null;
    
    if (req.file) {
        // ✅ Проверяем тип файла
        const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'video/mp4'];
        if (!allowedTypes.includes(req.file.mimetype)) {
            fs.unlinkSync(req.file.path);
            return res.status(400).json({ error: 'Invalid file type' });
        }
        filePath = '/uploads/' + req.file.filename;
        media = JSON.stringify({ type: req.file.mimetype.split('/')[0], path: filePath });
    }

    // ✅ Шифруем пароль секретного поста
    if (is_secret === 'true' && secret_password) {
        encryptedSecret = encryptSecret(secret_password, secret_password);
    }

    try {
        await safeRun(
            `INSERT INTO posts (user_id, title, content, hashtags, media, folder_id, is_secret, secret_password, file_path) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [req.userId, title, content, hashtags, media, folderId || null, 
             is_secret === 'true' ? 1 : 0, encryptedSecret, filePath]
        );
        res.json({ id: this.lastID });
    } catch(e) {
        res.status(500).json({ error: 'Failed to create post' });
    }
});

// ✅ Secure secret post access
app.post('/api/posts/secret', auth, async (req, res) => {
    const { section, password } = req.body;
    if (!password) return res.status(400).json({ error: 'Password required' });

    try {
        const posts = await safeAll(
            `SELECT p.*, u.username FROM posts p
             JOIN users u ON p.user_id = u.id
             WHERE p.is_secret = 1
             ORDER BY p.created_at DESC`
        );

        // ✅ Проверяем пароль для каждого поста
        const decryptedPosts = [];
        for (const post of posts) {
            try {
                const decrypted = decryptSecret(post.secret_password, password);
                if (decrypted) {
                    decryptedPosts.push(post);
                }
            } catch(e) {
                // Пароль не подходит
            }
        }

        res.json(decryptedPosts);
    } catch(e) {
        res.status(500).json({ error: 'Failed to get secret posts' });
    }
});

// ✅ SECURE COMMENTS
app.post('/api/comments', [
    auth,
    body('postId').isInt(),
    body('content').isString().isLength({ min: 1, max: 500 })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ error: 'Invalid input' });
    }

    const { postId, content } = req.body;

    try {
        // ✅ Проверяем, существует ли пост
        const post = await safeQuery('SELECT id FROM posts WHERE id = ?', [postId]);
        if (!post) {
            return res.status(404).json({ error: 'Post not found' });
        }

        await safeRun(
            'INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)',
            [postId, req.userId, content]
        );
        res.json({ id: this.lastID });
    } catch(e) {
        res.status(500).json({ error: 'Failed to create comment' });
    }
});

// ✅ DARK LOCKER с улучшенным шифрованием
app.post('/api/dark-locker', [
    auth,
    body('title').isString().isLength({ min: 1, max: 100 }),
    body('secret').isString().isLength({ min: 1 }),
    body('password').isString().isLength({ min: 8 })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ error: 'Invalid input' });
    }

    const { title, secret, password } = req.body;
    
    // ✅ Используем сильное шифрование
    const encrypted = encryptSecret(secret, password);

    try {
        await safeRun(
            'INSERT INTO dark_locker (user_id, title, encrypted_data) VALUES (?, ?, ?)',
            [req.userId, title, encrypted]
        );
        res.json({ id: this.lastID });
    } catch(e) {
        res.status(500).json({ error: 'Failed to save secret' });
    }
});

// ============ АУДИТ И ЛОГИ ============
// ✅ Добавляем логирование важных действий
function logAction(userId, action, details = '') {
    const logEntry = {
        timestamp: new Date().toISOString(),
        userId,
        action,
        details,
        ip: req?.ip || 'unknown'
    };
    fs.appendFileSync('audit.log', JSON.stringify(logEntry) + '\n');
}

// ============ БЕЗОПАСНЫЙ СТАРТ ============
app.listen(PORT, '127.0.0.1', () => { // ✅ Только localhost
    console.log(`Shadow Lanterns running securely on port ${PORT}`);
});
