const express = require('express');
const router = express.Router();
const db = require('../db'); // SQLite bağlantısı
const bcrypt = require('bcrypt');

// GET /verify?email=...
router.get('/', async (req, res) => {
  const email = req.query.email;
  if (!email) {
    return res.redirect('/register'); // email yoksa kayıt sayfasına yönlendir
  }

  res.render('verify', { email, error: null, success: null });
});

// POST /verify
router.post('/', async (req, res) => {
  const { email, code } = req.body;

  db.get('SELECT verification_code FROM users WHERE email = ?', [email], async (err, row) => {
    if (err) {
      console.error(err);
      return res.render('verify', { email, error: 'Bir hata oluştu.', success: null });
    }

    if (!row) {
      return res.render('verify', { email, error: 'Kullanıcı bulunamadı.', success: null });
    }

    if (row.verification_code === code) {
      db.run('UPDATE users SET is_verified = 1 WHERE email = ?', [email], (updateErr) => {
        if (updateErr) {
          console.error(updateErr);
          return res.render('verify', { email, error: 'Kayıt güncellenemedi.', success: null });
        }

        return res.render('verify', { email, error: null, success: 'Başarıyla doğrulandı! Artık giriş yapabilirsiniz.' });
      });
    } else {
      return res.render('verify', { email, error: 'Kod uyuşmuyor. Lütfen kontrol et.', success: null });
    }
  });
});

module.exports = router;
