const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const path = require('path');
const session = require('express-session');
const nodemailer = require('nodemailer');
const QRCode = require('qr-image');
const shortid = require('shortid');
const bcrypt = require('bcrypt');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Geçici e-posta sağlayıcıları (fake adresleri engellemek için)
const tempEmailDomains = ['mailinator.com', 'tempmail.com', '10minutemail.com'];

// Nodemailer transporter ayarları (Gmail)
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,    // .env dosyanızdaki e-posta
    pass: process.env.EMAIL_PASS     // .env dosyanızdaki uygulama şifresi
  },
  tls: { rejectUnauthorized: false }
});

function sendVerificationEmail(to, code) {
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to,
    subject: "Doğrulama Kodunuz",
    text: `Link kısaltma sitesine kaydolmak için doğrulama kodunuz: ${code}`,
  };
  return transporter.sendMail(mailOptions);
}

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
  secret: 'gizliKelimemiz123',
  resave: false,
  saveUninitialized: true
}));
app.use(express.static(path.join(__dirname, 'public')));

// Veritabanı bağlantısı ve tabloların oluşturulması
const db = new sqlite3.Database('./database.db', (err) => {
  if (err) console.error(err.message);
});

db.serialize(() => {
  // Geliştirme amaçlı tabloları sıfırlıyoruz. (Canlıya alırken DROP komutlarını kaldırın)
  db.run("DROP TABLE IF EXISTS clicks");
  db.run("DROP TABLE IF EXISTS reports");
  db.run("DROP TABLE IF EXISTS urls");
  db.run("DROP TABLE IF EXISTS users");

  // Kullanıcı tablosu: email, password, email_verified, verification_code
  db.run(`CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password TEXT,
    email_verified INTEGER DEFAULT 0,
    verification_code TEXT
  )`);

  // URL tablosu
  db.run(`CREATE TABLE urls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    original TEXT,
    short TEXT UNIQUE,
    created_at TEXT,
    reports INTEGER DEFAULT 0,
    user_id INTEGER,
    link_password TEXT,
    dangerous INTEGER DEFAULT 0,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  // Reports tablosu: "reason" ve "user_id" sütunlarını içeriyor.
  db.run(`CREATE TABLE reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    short TEXT,
    created_at TEXT,
    reason TEXT,
    user_id INTEGER,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  // Tıklama tablosu
  db.run(`CREATE TABLE clicks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_id INTEGER,
    click_time TEXT,
    ip TEXT,
    FOREIGN KEY(url_id) REFERENCES urls(id)
  )`);
});

/* ----------------------
   KULLANICI KAYIT VE E-POSTA DOĞRULAMA
------------------------- */

// Kayıt (POST /api/register)
// Kullanıcı e-posta ve şifre ile kayıt olur, geçici e-posta kontrolü yapılır,
// 6 haneli doğrulama kodu oluşturulur, e-posta gönderilir ve
// kayıt öncesinde email, session'a "tempEmail" olarak kaydedilir.
app.post('/api/register', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: 'E-posta ve şifre gerekli.' });

  const emailDomain = email.split('@')[1].toLowerCase();
  if (tempEmailDomains.includes(emailDomain)) {
    return res.status(400).json({ error: 'Bu e-posta adresi geçici (fake) görünüyor. Lütfen gerçek bir e-posta adresi girin.' });
  }

  const hashed = bcrypt.hashSync(password, 10);
  const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();

  db.run('INSERT INTO users (email, password, verification_code) VALUES (?, ?, ?)', [email, hashed, verificationCode], function(err) {
    if (err) return res.status(500).json({ error: 'Bu e-posta zaten alınmış olabilir.' });

    sendVerificationEmail(email, verificationCode)
      .then(() => {
        req.session.tempEmail = email;
        res.json({ message: `${email} adresine doğrulama kodu gönderildi. Lütfen doğrulama panelini kullanın.` });
      })
      .catch((error) => {
        console.error("Mail gönderim hatası:", error);
        res.status(500).json({ error: 'Doğrulama e-postası gönderilemedi.' });
      });
  });
});

// E-posta Doğrulama (POST /api/verify-email)
// Kullanıcı, doğrulama panelinde girilen kodu gönderir. Kod doğru ise kayıt tamamlanır.
app.post('/api/verify-email', (req, res) => {
  const { email, verificationCode } = req.body;
  if (!email || !verificationCode)
    return res.status(400).json({ error: 'E-posta ve doğrulama kodu gerekli.' });
  db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
    if (err || !user) return res.status(404).json({ error: 'Kullanıcı bulunamadı.' });
    if (user.verification_code === verificationCode) {
      db.run('UPDATE users SET email_verified = 1, verification_code = NULL WHERE email = ?', [email]);
      res.json({ message: 'E-posta doğrulaması başarılı. Kayıt tamamlandı.' });
    } else {
      res.status(400).json({ error: 'Doğrulama kodu yanlış.' });
    }
  });
});

/* ----------------------
   GİRİŞ / ÇIKIŞ İŞLEMLERİ
------------------------- */

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
    if (err || !user)
      return res.status(401).json({ error: 'E-posta veya şifre yanlış.' });
    if (!bcrypt.compareSync(password, user.password))
      return res.status(401).json({ error: 'E-posta veya şifre yanlış.' });
    if (user.email_verified != 1)
      return res.status(403).json({ error: 'E-posta doğrulaması yapılmamış. Lütfen e-posta kutunuzu kontrol edin.' });
    req.session.userId = user.id;
    req.session.username = email;
    res.json({ message: 'Giriş başarılı', username: email });
  });
});

app.get('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ message: 'Çıkış yapıldı.' });
});

/* ----------------------
   LİNK İŞLEMLERİ (Kısaltma, Yönlendirme, Şifre Koruma, QR Kod)
------------------------- */

// URL kısaltma (POST /api/shorten)
// Eğer kullanıcı özel link girmişse (customLink) onu kullan, aksi halde random üret.
app.post('/api/shorten', (req, res) => {
  if (!req.session.userId)
    return res.status(401).json({ error: 'Link kısaltmak için giriş yapmalısınız.' });
  const { original, link_password, customLink } = req.body;

  let short = "";
  if (customLink && customLink.trim() !== "") {
    short = customLink.trim();
    // Özel link zaten kullanılmış mı kontrol et
    db.get('SELECT * FROM urls WHERE short = ?', [short], (err, row) => {
      if (row) {
        return res.status(400).json({ error: 'Bu özel kısa link zaten kullanılmış.' });
      } else {
        insertLink();
      }
    });
  } else {
    short = shortid.generate();
    insertLink();
  }

  function insertLink() {
    const createdAt = new Date().toISOString();
    db.run('INSERT INTO urls (original, short, created_at, user_id, link_password) VALUES (?, ?, ?, ?, ?)',
      [original, short, createdAt, req.session.userId, link_password || ''], function(err) {
        if (err) return res.status(500).json({ error: 'Link kısaltılamadı.' });
        res.json({ message: `Kısaltılmış link: ${req.protocol}://${req.get('host')}/${short}` });
      });
  }
});

// Yönlendirme (GET /:short)
app.get('/:short', (req, res, next) => {
  const short = req.params.short;
  // Admin, adminrapor veya dashboard yolları hariç
  if (short === 'admin123' || short === 'admin123rapor' || short === 'dashboard')
    return next();

  db.get('SELECT * FROM urls WHERE short = ?', [short], (err, row) => {
    if (err) return res.status(500).send(err.message);
    if (!row) return res.status(404).send('Link bulunamadı.');

    if (row.dangerous == 1 && !req.query.confirm) {
      return res.send(`
        <html>
          <head>
            <title>Uyarı: Tehlikeli Link</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
          </head>
          <body class="bg-light">
            <div class="container mt-4">
              <h2>Uyarı!</h2>
              <p>Bu link potansiyel olarak tehlikeli olabilir. Devam etmek istiyor musunuz?</p>
              <a href="/${short}?confirm=true" class="btn btn-warning">Devam Et</a>
            </div>
          </body>
        </html>
      `);
    }

    if (row.link_password) {
      return res.redirect('/proceed/' + short);
    }

    const clickTime = new Date().toISOString();
    db.run('INSERT INTO clicks (url_id, click_time, ip) VALUES (?, ?, ?)', [row.id, clickTime, req.ip]);
    res.redirect(row.original);
  });
});

// Şifre korumalı linkler için (GET /proceed/:short)
app.get('/proceed/:short', (req, res) => {
  const short = req.params.short;
  db.get('SELECT * FROM urls WHERE short = ?', [short], (err, row) => {
    if (!row) return res.status(404).send("Link bulunamadı.");
    if (row.link_password) {
      return res.send(`
        <html>
          <head>
            <title>Şifre Gerekli</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
          </head>
          <body class="bg-light">
            <div class="container mt-4">
              <h2>Bu link şifre korumalıdır.</h2>
              <form method="POST" action="/verify/${short}">
                <div class="mb-3">
                  <input type="password" name="password" class="form-control" placeholder="Link Şifresi" required>
                </div>
                <button type="submit" class="btn btn-primary">Gönder</button>
              </form>
            </div>
          </body>
        </html>
      `);
    } else {
      const clickTime = new Date().toISOString();
      db.run('INSERT INTO clicks (url_id, click_time, ip) VALUES (?, ?, ?)', [row.id, clickTime, req.ip]);
      res.redirect(row.original);
    }
  });
});

// Şifre doğrulama (POST /verify/:short)
app.post('/verify/:short', (req, res) => {
  const short = req.params.short;
  const password = req.body.password;
  db.get('SELECT * FROM urls WHERE short = ?', [short], (err, row) => {
    if (!row) return res.status(404).send("Link bulunamadı.");
    if (row.link_password === password) {
      const clickTime = new Date().toISOString();
      db.run('INSERT INTO clicks (url_id, click_time, ip) VALUES (?, ?, ?)', [row.id, clickTime, req.ip]);
      res.redirect(row.original);
    } else {
      res.send(`Yanlış şifre. <a href="/proceed/${short}">Tekrar Deneyin</a>`);
    }
  });
});

// QR Kod Oluşturma (GET /api/qrcode?short=xxx)
app.get('/api/qrcode', (req, res) => {
  const short = req.query.short;
  if (!short) return res.status(400).send('Kısaltılmış link gerekli.');
  db.get('SELECT * FROM urls WHERE short = ?', [short], (err, row) => {
    if (err || !row) return res.status(404).send('Link bulunamadı.');
    const fullUrl = req.protocol + '://' + req.get('host') + '/' + short;
    try {
      const codeBuffer = QRCode.imageSync(fullUrl, { type: 'png' });
      const base64Data = codeBuffer.toString('base64');
      res.json({ qrCode: "data:image/png;base64," + base64Data });
    } catch (e) {
      res.status(500).send('QR kod oluşturulamadı.');
    }
  });
});

// Raporlama (POST /api/report)
app.post('/api/report', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Rapor göndermek için giriş yapmalısınız.' });
  }
  const { short, reason } = req.body;
  if (!short) return res.status(400).json({ error: 'Kısaltılmış link gerekli.' });
  const createdAt = new Date().toISOString();
  db.get('SELECT * FROM reports WHERE short = ? AND user_id = ?', [short, req.session.userId], (err, reportRow) => {
    if (reportRow) {
      return res.status(400).json({ error: 'Bu linki zaten raporladınız.' });
    }
    db.get('SELECT id FROM urls WHERE short = ?', [short], (err, row) => {
      if (err || !row) return res.status(404).json({ error: 'Link bulunamadı.' });
      db.run('INSERT INTO reports (short, created_at, reason, user_id) VALUES (?, ?, ?, ?)', [short, createdAt, reason || '', req.session.userId], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        db.run('UPDATE urls SET reports = reports + 1 WHERE id = ?', [row.id]);
        res.json({ message: 'Raporunuz gönderildi.' });
      });
    });
  });
});

/* ----------------------
   ADMIN PANELİ VE RAPOR PANELİ
------------------------- */

// ADMIN PANELİ (/admin123)
app.all('/admin123', (req, res) => {
  if (req.method === 'POST') {
    const { username, password } = req.body;
    if (username === 'qw' && password === 'qwqw') {
      req.session.admin = true;
      return res.redirect('/admin123');
    } else {
      return res.send("Hatalı kullanıcı adı veya şifre. <a href='/admin123'>Tekrar deneyin</a>");
    }
  } else {
    if (!req.session.admin) {
      return res.send(`
        <html>
          <head>
            <title>Admin Giriş</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
          </head>
          <body class="bg-light">
            <div class="container mt-4">
              <h2>Admin Girişi</h2>
              <form method="POST" action="/admin123">
                <div class="mb-3">
                  <input type="text" name="username" class="form-control" placeholder="Kullanıcı Adı" required>
                </div>
                <div class="mb-3">
                  <input type="password" name="password" class="form-control" placeholder="Şifre" required>
                </div>
                <button type="submit" class="btn btn-primary">Giriş Yap</button>
              </form>
            </div>
          </body>
        </html>
      `);
    } else {
      db.all(`SELECT id, original, short, datetime(created_at) as created_at, reports
              FROM urls ORDER BY datetime(created_at) DESC`, (err, rows) => {
        if (err) return res.status(500).send('Veritabanı hatası.');
        let html = `
          <html>
            <head>
              <title>Admin Paneli</title>
              <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
            </head>
            <body class="bg-light">
              <div class="container mt-4">
                <h1>Admin Paneli</h1>
                <p><a href="/api/logout">Çıkış Yap</a> | <a href="/admin123rapor">Rapor Paneli</a></p>
                <table class="table table-bordered">
                  <tr>
                    <th>ID</th>
                    <th>Oluşturulma Tarihi</th>
                    <th>Orijinal Link</th>
                    <th>Kısaltılmış Link</th>
                    <th>Rapor Sayısı</th>
                    <th>İşlem</th>
                  </tr>`;
        rows.forEach(row => {
          html += `
                  <tr>
                    <td>${row.id}</td>
                    <td>${row.created_at}</td>
                    <td><a href="${row.original}" target="_blank">${row.original}</a></td>
                    <td><a href="${req.protocol + '://' + req.get('host') + '/' + row.short}" target="_blank">${row.short}</a></td>
                    <td>${row.reports}</td>
                    <td>
                      <form method="POST" action="/api/delete" onsubmit="return confirm('Bu linki silmek istediğinize emin misiniz?');">
                        <input type="hidden" name="short" value="${row.short}">
                        <button type="submit" class="btn btn-danger btn-sm">Sil</button>
                      </form>
                    </td>
                  </tr>`;
        });
        html += `</table></div></body></html>`;
        res.send(html);
      });
    }
  }
});

// ADMIN RAPOR PANELİ (/admin123rapor)
app.all('/admin123rapor', (req, res) => {
  if (req.method === 'POST') {
    const { username, password } = req.body;
    if (username === 'qw' && password === 'qwqw') {
      req.session.admin = true;
      return res.redirect('/admin123rapor');
    } else {
      return res.send("Hatalı kullanıcı adı veya şifre. <a href='/admin123rapor'>Tekrar deneyin</a>");
    }
  } else {
    if (!req.session.admin) {
      return res.send(`
        <html>
          <head>
            <title>Admin Rapor Giriş</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
          </head>
          <body class="bg-light">
            <div class="container mt-4">
              <h2>Admin Rapor Girişi</h2>
              <form method="POST" action="/admin123rapor">
                <div class="mb-3">
                  <input type="text" name="username" class="form-control" placeholder="Kullanıcı Adı" required>
                </div>
                <div class="mb-3">
                  <input type="password" name="password" class="form-control" placeholder="Şifre" required>
                </div>
                <button type="submit" class="btn btn-primary">Giriş Yap</button>
              </form>
            </div>
          </body>
        </html>
      `);
    } else {
      db.all(`SELECT u.id, u.short, datetime(u.created_at) as created_at, u.original, 
                    GROUP_CONCAT(r.reason, '; ') as reasons, u.dangerous, u.reports
              FROM urls u
              LEFT JOIN reports r ON u.short = r.short
              WHERE u.dangerous = 1 OR u.reports > 0
              GROUP BY u.id
              ORDER BY datetime(u.created_at) DESC`, (err, rows) => {
        if (err) return res.status(500).send('Veritabanı hatası.');
        let html = `
          <html>
            <head>
              <title>Admin Rapor Paneli</title>
              <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
            </head>
            <body class="bg-light">
              <div class="container mt-4">
                <h1>Admin Rapor Paneli</h1>
                <p><a href="/admin123">Admin Paneline Dön</a></p>
                <table class="table table-bordered">
                  <tr>
                    <th>ID</th>
                    <th>Kısaltılmış Link</th>
                    <th>Orijinal Link</th>
                    <th>Oluşturulma Tarihi</th>
                    <th>Rapor Nedeni</th>
                    <th>Tehlikeli</th>
                    <th>Rapor Sayısı</th>
                    <th>İşlem</th>
                  </tr>`;
        rows.forEach(row => {
          html += `
                  <tr>
                    <td>${row.id}</td>
                    <td><a href="${req.protocol + '://' + req.get('host') + '/' + row.short}" target="_blank">${row.short}</a></td>
                    <td><a href="${row.original}" target="_blank">${row.original}</a></td>
                    <td>${row.created_at}</td>
                    <td>${row.reasons || ''}</td>
                    <td>${row.dangerous == 1 ? '<span class="badge bg-danger">Evet</span>' : '<span class="badge bg-success">Hayır</span>'}</td>
                    <td>${row.reports}</td>
                    <td>
                      <form method="POST" action="/api/delete" onsubmit="return confirm('Bu linki silmek istediğinize emin misiniz?');">
                        <input type="hidden" name="short" value="${row.short}">
                        <button type="submit" class="btn btn-danger btn-sm">Sil</button>
                      </form>
                    </td>
                  </tr>`;
        });
        html += `</table></div></body></html>`;
        res.send(html);
      });
    }
  }
});

// ADMIN LINK SİLME (POST /api/delete)
app.post('/api/delete', (req, res) => {
  if (!req.session.admin) return res.status(403).send('Yetkisiz erişim.');
  const { short } = req.body;
  db.run('DELETE FROM urls WHERE short = ?', [short], function(err) {
    if (err) return res.status(500).send('Link silinemedi.');
    res.redirect(req.headers.referer || '/admin123');
  });
});

// Kullanıcı Dashboard (GET /dashboard)
app.get('/dashboard', (req, res) => {
  if (!req.session.userId) return res.redirect('/');
  db.all('SELECT * FROM urls WHERE user_id = ? ORDER BY datetime(created_at) DESC', [req.session.userId], (err, rows) => {
    if (err) return res.status(500).send('Veritabanı hatası.');
    let html = `
      <html>
        <head>
          <title>Kullanıcı Dashboard</title>
          <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        </head>
        <body class="bg-light">
          <div class="container mt-4">
            <h1>${req.session.username} - Dashboard</h1>
            <p><a href="/api/logout">Çıkış Yap</a></p>
            <table class="table table-bordered">
              <tr>
                <th>ID</th>
                <th>Oluşturulma Tarihi</th>
                <th>Orijinal Link</th>
                <th>Kısaltılmış Link</th>
                <th>Rapor Sayısı</th>
              </tr>`;
    rows.forEach(row => {
      html += `
              <tr>
                <td>${row.id}</td>
                <td>${new Date(row.created_at).toLocaleString()}</td>
                <td><a href="${row.original}" target="_blank">${row.original}</a></td>
                <td><a href="${req.protocol + '://' + req.get('host') + '/' + row.short}" target="_blank">${row.short}</a></td>
                <td>${row.reports}</td>
              </tr>`;
    });
    html += `</table></div></body></html>`;
    res.send(html);
  });
});

// Diğer tüm isteklerde index.html gönderilir (client-side routing)
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => console.log(`Sunucu ${PORT} portunda çalışıyor.`));
