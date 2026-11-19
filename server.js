const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const Database = require('better-sqlite3');

const app = express();
const PORT = process.env.PORT || 3000;

const ADMIN_PHONE = String(process.env.ADMIN_PHONE || '783553915').trim();
const ADMIN_DEFAULT_PASS = String(process.env.ADMIN_DEFAULT_PASS || 'Barq@2026');

app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true }));

const publicDir = path.join(__dirname, 'public');
if (fs.existsSync(publicDir)) {
  app.use(express.static(publicDir));
}

const dbPath = process.env.DB_PATH || path.join(__dirname, 'barq_wallet.db');
const db = new Database(dbPath);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(password), salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  if (!stored || !stored.includes(':')) return false;
  const [salt, originalHash] = stored.split(':');
  const derived = crypto.scryptSync(String(password), salt, 64);
  const original = Buffer.from(originalHash, 'hex');
  if (derived.length !== original.length) return false;
  return crypto.timingSafeEqual(derived, original);
}

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function generateOtpCode() {
  return String(crypto.randomInt(100000, 999999));
}

function generatePosCode() {
  return 'POS-' + String(crypto.randomInt(100000, 999999));
}

function nowIso() {
  return new Date().toISOString();
}

// إنشاء الجداول الأساسية لنظام محفظة البرق
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    phone TEXT NOT NULL UNIQUE,
    full_name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user', -- 'user' | 'merchant' | 'admin'
    is_merchant INTEGER NOT NULL DEFAULT 0,
    pos_code TEXT UNIQUE,
    kyc_status TEXT NOT NULL DEFAULT 'unverified', -- 'unverified' | 'pending' | 'verified' | 'rejected'
    kyc_id_number TEXT,
    kyc_notes TEXT,
    daily_limit REAL NOT NULL DEFAULT 50000,
    monthly_limit REAL NOT NULL DEFAULT 500000,
    status TEXT NOT NULL DEFAULT 'active', -- 'active' | 'frozen'
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER UNIQUE,
    account_code TEXT NOT NULL UNIQUE,
    account_type TEXT NOT NULL, -- 'wallet' | 'system_vault' | 'settlement' | 'fee_revenue'
    balance REAL NOT NULL DEFAULT 0,
    currency TEXT NOT NULL DEFAULT 'YER',
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tx_ref TEXT NOT NULL UNIQUE,
    tx_type TEXT NOT NULL, -- 'transfer' | 'pos_payment' | 'admin_adjust' | 'topup'
    from_account_id INTEGER,
    to_account_id INTEGER,
    amount REAL NOT NULL,
    fee REAL NOT NULL DEFAULT 0,
    note TEXT,
    status TEXT NOT NULL DEFAULT 'completed',
    created_by_admin INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    FOREIGN KEY (from_account_id) REFERENCES accounts(id),
    FOREIGN KEY (to_account_id) REFERENCES accounts(id)
  );

  CREATE TABLE IF NOT EXISTS ledger_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tx_id INTEGER NOT NULL,
    account_id INTEGER NOT NULL,
    direction TEXT NOT NULL, -- 'debit' | 'credit'
    amount REAL NOT NULL,
    balance_after REAL NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (tx_id) REFERENCES transactions(id),
    FOREIGN KEY (account_id) REFERENCES accounts(id)
  );

  CREATE TABLE IF NOT EXISTS otp_challenges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    phone TEXT NOT NULL,
    purpose TEXT NOT NULL, -- 'admin_login'
    otp_code TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    phone TEXT NOT NULL,
    role TEXT NOT NULL,
    otp_verified INTEGER NOT NULL DEFAULT 0,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

function ensureSystemAccounts() {
  const sysAccounts = [
    { code: 'SYS-VAULT-MAIN', type: 'system_vault', balance: 100000000 },
    { code: 'SYS-FEE-REVENUE', type: 'fee_revenue', balance: 0 }
  ];
  const insertAcc = db.prepare(`
    INSERT OR IGNORE INTO accounts (user_id, account_code, account_type, balance, currency, updated_at)
    VALUES (NULL, ?, ?, ?, 'YER', ?)
  `);
  for (const acc of sysAccounts) {
    insertAcc.run(acc.code, acc.type, acc.balance, nowIso());
  }
}

function ensureAdminAccount() {
  ensureSystemAccounts();
  const existing = db.prepare('SELECT * FROM users WHERE phone = ?').get(ADMIN_PHONE);
  if (!existing) {
    const info = db.prepare(`
      INSERT INTO users (
        phone, full_name, password_hash, role, is_merchant, pos_code,
        kyc_status, daily_limit, monthly_limit, status, created_at
      ) VALUES (?, ?, ?, 'admin', 1, ?, 'verified', 999999999, 999999999, 'active', ?)
    `).run(
      ADMIN_PHONE,
      'إدارة محفظة البرق',
      hashPassword(ADMIN_DEFAULT_PASS),
      'POS-ADMIN',
      nowIso()
    );

    db.prepare(`
      INSERT INTO accounts (user_id, account_code, account_type, balance, currency, updated_at)
      VALUES (?, ?, 'wallet', 0, 'YER', ?)
    `).run(info.lastInsertRowid, `WLT-${ADMIN_PHONE}`, nowIso());
  } else {
    // ضمان بقاء صلاحية الإدارة محصورة برقم المدير المعتمد فقط
    db.prepare(`
      UPDATE users SET role = 'admin', status = 'active' WHERE phone = ?
    `).run(ADMIN_PHONE);
    db.prepare(`
      UPDATE users SET role = 'user' WHERE phone != ? AND role = 'admin'
    `).run(ADMIN_PHONE);

    const acc = db.prepare('SELECT id FROM accounts WHERE user_id = ?').get(existing.id);
    if (!acc) {
      db.prepare(`
        INSERT INTO accounts (user_id, account_code, account_type, balance, currency, updated_at)
        VALUES (?, ?, 'wallet', 0, 'YER', ?)
      `).run(existing.id, `WLT-${ADMIN_PHONE}`, nowIso());
    }
  }
}

ensureAdminAccount();

function getUserWalletAccount(userId) {
  let acc = db.prepare('SELECT * FROM accounts WHERE user_id = ?').get(userId);
  if (!acc) {
    const user = db.prepare('SELECT phone FROM users WHERE id = ?').get(userId);
    const code = `WLT-${user ? user.phone : userId}`;
    const info = db.prepare(`
      INSERT INTO accounts (user_id, account_code, account_type, balance, currency, updated_at)
      VALUES (?, ?, 'wallet', 0, 'YER', ?)
    `).run(userId, code, nowIso());
    acc = db.prepare('SELECT * FROM accounts WHERE id = ?').get(info.lastInsertRowid);
  }
  return acc;
}

function getSystemAccount(accountCode) {
  return db.prepare('SELECT * FROM accounts WHERE account_code = ?').get(accountCode);
}

// تنفيذ قيد محاسبي مزدوج آمن داخل معاملة قاعدة بيانات
const executeDoubleEntry = db.transaction(({
  txType,
  fromAccountId,
  toAccountId,
  amount,
  fee = 0,
  note = '',
  createdByAdmin = 0
}) => {
  const numAmount = Number(amount);
  const numFee = Number(fee || 0);
  if (!Number.isFinite(numAmount) || numAmount <= 0) {
    throw new Error('المبلغ يجب أن يكون أكبر من صفر');
  }
  if (!Number.isFinite(numFee) || numFee < 0) {
    throw new Error('الرسوم غير صالحة');
  }

  const totalDebitFromSender = numAmount + numFee;
  let fromAcc = null;
  let toAcc = null;

  if (fromAccountId) {
    fromAcc = db.prepare('SELECT * FROM accounts WHERE id = ?').get(fromAccountId);
    if (!fromAcc) throw new Error('الحساب المرسل غير موجود');
    if (fromAcc.account_type !== 'system_vault' && Number(fromAcc.balance) < totalDebitFromSender) {
      throw new Error('الرصيد غير كافٍ لإتمام العملية');
    }
  }

  if (toAccountId) {
    toAcc = db.prepare('SELECT * FROM accounts WHERE id = ?').get(toAccountId);
    if (!toAcc) throw new Error('الحساب المستلم غير موجود');
  }

  const txRef = 'BRQ-' + Date.now() + '-' + crypto.randomInt(1000, 9999);
  const timestamp = nowIso();

  const txInfo = db.prepare(`
    INSERT INTO transactions (
      tx_ref, tx_type, from_account_id, to_account_id, amount, fee, note, status, created_by_admin, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'completed', ?, ?)
  `).run(
    txRef,
    txType,
    fromAccountId || null,
    toAccountId || null,
    numAmount,
    numFee,
    note || '',
    createdByAdmin ? 1 : 0,
    timestamp
  );

  const txId = txInfo.lastInsertRowid;
  const insertLedger = db.prepare(`
    INSERT INTO ledger_entries (tx_id, account_id, direction, amount, balance_after, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `);
  const updateBalance = db.prepare(`
    UPDATE accounts SET balance = ?, updated_at = ? WHERE id = ?
  `);

  if (fromAcc) {
    const newFromBal = Number((Number(fromAcc.balance) - totalDebitFromSender).toFixed(2));
    updateBalance.run(newFromBal, timestamp, fromAcc.id);
    insertLedger.run(txId, fromAcc.id, 'debit', totalDebitFromSender, newFromBal, timestamp);
  }

  if (toAcc) {
    const newToBal = Number((Number(toAcc.balance) + numAmount).toFixed(2));
    updateBalance.run(newToBal, timestamp, toAcc.id);
    insertLedger.run(txId, toAcc.id, 'credit', numAmount, newToBal, timestamp);
  }

  if (numFee > 0) {
    const feeAcc = getSystemAccount('SYS-FEE-REVENUE');
    if (feeAcc) {
      const newFeeBal = Number((Number(feeAcc.balance) + numFee).toFixed(2));
      updateBalance.run(newFeeBal, timestamp, feeAcc.id);
      insertLedger.run(txId, feeAcc.id, 'credit', numFee, newFeeBal, timestamp);
    }
  }

  return { txId, txRef, amount: numAmount, fee: numFee, createdAt: timestamp };
});

// التحقق من الجلسة
function authRequired(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
  if (!token) {
    return res.status(401).json({ ok: false, error: 'يلزم تسجيل الدخول أولاً' });
  }

  const session = db.prepare('SELECT * FROM sessions WHERE token = ?').get(token);
  if (!session || new Date(session.expires_at) < new Date()) {
    return res.status(401).json({ ok: false, error: 'انتهت الجلسة، يرجى تسجيل الدخول مجدداً' });
  }

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(session.user_id);
  if (!user || user.status === 'frozen') {
    return res.status(403).json({ ok: false, error: 'الحساب غير نشط أو مجمّد' });
  }

  req.session = session;
  req.user = user;
  next();
}

// صلاحية الإدارة العليا الحصرية لرقم 783553915 بعد تأكيد OTP
function adminRequired(req, res, next) {
  if (
    req.user.phone !== ADMIN_PHONE ||
    req.user.role !== 'admin' ||
    Number(req.session.otp_verified) !== 1
  ) {
    return res.status(403).json({
      ok: false,
      error: 'الوصول الإداري محصور برقم الإدارة المعتمد بعد إتمام التحقق عبر OTP'
    });
  }
  next();
}

// فحص حالة الخادم
app.get('/api/health', (req, res) => {
  res.json({ ok: true, service: 'محفظة البرق - Al-Barq Wallet', time: nowIso() });
});

// تسجيل حساب مستخدم جديد
app.post('/api/auth/register', (req, res) => {
  try {
    const phone = String(req.body.phone || '').trim();
    const fullName = String(req.body.full_name || '').trim();
    const password = String(req.body.password || '');

    if (!phone || !fullName || password.length < 4) {
      return res.status(400).json({ ok: false, error: 'يرجى إدخال الاسم ورقم الهاتف وكلمة مرور صالحة' });
    }

    if (phone === ADMIN_PHONE) {
      return res.status(400).json({ ok: false, error: 'هذا الرقم مخصص للإدارة، استخدم شاشة دخول الإدارة' });
    }

    const exists = db.prepare('SELECT id FROM users WHERE phone = ?').get(phone);
    if (exists) {
      return res.status(409).json({ ok: false, error: 'رقم الهاتف مسجل مسبقاً' });
    }

    const timestamp = nowIso();
    const info = db.prepare(`
      INSERT INTO users (
        phone, full_name, password_hash, role, is_merchant, pos_code,
        kyc_status, daily_limit, monthly_limit, status, created_at
      ) VALUES (?, ?, ?, 'user', 0, NULL, 'unverified', 50000, 500000, 'active', ?)
    `).run(phone, fullName, hashPassword(password), timestamp);

    const userId = info.lastInsertRowid;
    db.prepare(`
      INSERT INTO accounts (user_id, account_code, account_type, balance, currency, updated_at)
      VALUES (?, ?, 'wallet', 0, 'YER', ?)
    `).run(userId, `WLT-${phone}`, timestamp);

    const token = generateToken();
    const expiresAt = new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString();
    db.prepare(`
      INSERT INTO sessions (token, user_id, phone, role, otp_verified, expires_at, created_at)
      VALUES (?, ?, ?, 'user', 0, ?, ?)
    `).run(token, userId, phone, expiresAt, timestamp);

    const user = db.prepare('SELECT id, phone, full_name, role, is_merchant, pos_code, kyc_status, daily_limit, monthly_limit, status FROM users WHERE id = ?').get(userId);
    const wallet = getUserWalletAccount(userId);

    res.json({ ok: true, token, user, wallet });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// تسجيل الدخول (للمستخدمين أو بدء خطوة التحقق للإدارة)
app.post('/api/auth/login', (req, res) => {
  try {
    const phone = String(req.body.phone || '').trim();
    const password = String(req.body.password || '');

    if (!phone || !password) {
      return res.status(400).json({ ok: false, error: 'يرجى إدخال رقم الهاتف وكلمة المرور' });
    }

    const user = db.prepare('SELECT * FROM users WHERE phone = ?').get(phone);
    if (!user || !verifyPassword(password, user.password_hash)) {
      return res.status(401).json({ ok: false, error: 'بيانات الدخول غير صحيحة' });
    }

    if (user.status === 'frozen') {
      return res.status(403).json({ ok: false, error: 'الحساب مجمّد حالياً' });
    }

    // إذا كان رقم الإدارة المعتمد 783553915، يُشترط إتمام OTP
    if (user.phone === ADMIN_PHONE) {
      const otpCode = generateOtpCode();
      const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();
      const timestamp = nowIso();

      db.prepare('UPDATE otp_challenges SET used = 1 WHERE phone = ? AND used = 0').run(ADMIN_PHONE);
      db.prepare(`
        INSERT INTO otp_challenges (phone, purpose, otp_code, expires_at, used, created_at)
        VALUES (?, 'admin_login', ?, ?, 0, ?)
      `).run(ADMIN_PHONE, otpCode, expiresAt, timestamp);

      return res.json({
        ok: true,
        requires_otp: true,
        phone: ADMIN_PHONE,
        message: 'تم إرسال رمز التحقق OTP لتأكيد دخول الإدارة',
        // يُعاد في بيئة الاختبار لتسهيل التحقق الفوري حتى ربط بوابة SMS خارجية
        dev_otp_code: otpCode
      });
    }

    const token = generateToken();
    const timestamp = nowIso();
    const expiresAt = new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString();
    db.prepare(`
      INSERT INTO sessions (token, user_id, phone, role, otp_verified, expires_at, created_at)
      VALUES (?, ?, ?, ?, 0, ?, ?)
    `).run(token, user.id, user.phone, user.role, expiresAt, timestamp);

    const safeUser = db.prepare('SELECT id, phone, full_name, role, is_merchant, pos_code, kyc_status, daily_limit, monthly_limit, status FROM users WHERE id = ?').get(user.id);
    const wallet = getUserWalletAccount(user.id);

    res.json({ ok: true, requires_otp: false, token, user: safeUser, wallet });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// تأكيد رمز OTP لدخول الإدارة الحصرية (783553915)
app.post('/api/auth/verify-otp', (req, res) => {
  try {
    const phone = String(req.body.phone || '').trim();
    const otpCode = String(req.body.otp_code || '').trim();

    if (phone !== ADMIN_PHONE) {
      return res.status(403).json({ ok: false, error: 'رمز OTP الإداري مخصص لرقم الإدارة فقط' });
    }

    const challenge = db.prepare(`
      SELECT * FROM otp_challenges
      WHERE phone = ? AND purpose = 'admin_login' AND used = 0
      ORDER BY id DESC LIMIT 1
    `).get(ADMIN_PHONE);

    if (!challenge || challenge.otp_code !== otpCode) {
      return res.status(400).json({ ok: false, error: 'رمز OTP غير صحيح' });
    }

    if (new Date(challenge.expires_at) < new Date()) {
      return res.status(400).json({ ok: false, error: 'انتهت صلاحية رمز OTP، يرجى إعادة المحاولة' });
    }

    db.prepare('UPDATE otp_challenges SET used = 1 WHERE id = ?').run(challenge.id);

    const adminUser = db.prepare('SELECT * FROM users WHERE phone = ?').get(ADMIN_PHONE);
    const token = generateToken();
    const timestamp = nowIso();
    const expiresAt = new Date(Date.now() + 24 * 3600 * 1000).toISOString();

    db.prepare(`
      INSERT INTO sessions (token, user_id, phone, role, otp_verified, expires_at, created_at)
      VALUES (?, ?, ?, 'admin', 1, ?, ?)
    `).run(token, adminUser.id, ADMIN_PHONE, expiresAt, timestamp);

    const safeUser = db.prepare('SELECT id, phone, full_name, role, is_merchant, pos_code, kyc_status, daily_limit, monthly_limit, status FROM users WHERE id = ?').get(adminUser.id);
    const wallet = getUserWalletAccount(adminUser.id);

    res.json({ ok: true, token, user: safeUser, wallet });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// بيانات الحساب الحالي والرصيد والعمليات الأخيرة
app.get('/api/wallet/me', authRequired, (req, res) => {
  const wallet = getUserWalletAccount(req.user.id);
  const recentTxs = db.prepare(`
    SELECT t.*,
      fa.account_code AS from_code,
      ta.account_code AS to_code
    FROM transactions t
    LEFT JOIN accounts fa ON t.from_account_id = fa.id
    LEFT JOIN accounts ta ON t.to_account_id = ta.id
    WHERE t.from_account_id = ? OR t.to_account_id = ?
    ORDER BY t.id DESC LIMIT 30
  `).all(wallet.id, wallet.id);

  const safeUser = db.prepare('SELECT id, phone, full_name, role, is_merchant, pos_code, kyc_status, kyc_id_number, kyc_notes, daily_limit, monthly_limit, status FROM users WHERE id = ?').get(req.user.id);
  res.json({ ok: true, user: safeUser, wallet, transactions: recentTxs });
});

// تفعيل نقطة بيع POS للتاجر أو المستخدم
app.post('/api/pos/activate', authRequired, (req, res) => {
  try {
    let posCode = req.user.pos_code;
    if (!posCode) {
      do {
        posCode = generatePosCode();
      } while (db.prepare('SELECT id FROM users WHERE pos_code = ?').get(posCode));
    }

    db.prepare('UPDATE users SET is_merchant = 1, pos_code = ? WHERE id = ?').run(posCode, req.user.id);
    const updated = db.prepare('SELECT id, phone, full_name, is_merchant, pos_code FROM users WHERE id = ?').get(req.user.id);
    res.json({ ok: true, user: updated, pos_code: posCode });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// التحويل بين المحافظ برقم الهاتف
app.post('/api/wallet/transfer', authRequired, (req, res) => {
  try {
    const toPhone = String(req.body.to_phone || '').trim();
    const amount = Number(req.body.amount);
    const note = String(req.body.note || 'تحويل محفظة البرق').trim();

    if (!toPhone || !Number.isFinite(amount) || amount <= 0) {
      return res.status(400).json({ ok: false, error: 'يرجى إدخال رقم المستلم ومبلغ صحيح' });
    }
    if (toPhone === req.user.phone) {
      return res.status(400).json({ ok: false, error: 'لا يمكن التحويل إلى نفس الحساب' });
    }
    if (amount > Number(req.user.daily_limit)) {
      return res.status(400).json({ ok: false, error: 'المبلغ يتجاوز الحد اليومي المسموح للحساب' });
    }

    const recipient = db.prepare('SELECT * FROM users WHERE phone = ?').get(toPhone);
    if (!recipient || recipient.status === 'frozen') {
      return res.status(404).json({ ok: false, error: 'حساب المستلم غير موجود أو مجمّد' });
    }

    const senderWallet = getUserWalletAccount(req.user.id);
    const recipientWallet = getUserWalletAccount(recipient.id);

    const result = executeDoubleEntry({
      txType: 'transfer',
      fromAccountId: senderWallet.id,
      toAccountId: recipientWallet.id,
      amount,
      fee: 0,
      note: `${note} (${req.user.phone} -> ${recipient.phone})`
    });

    res.json({ ok: true, transaction: result, balance: getUserWalletAccount(req.user.id).balance });
  } catch (err) {
    res.status(400).json({ ok: false, error: err.message });
  }
});

// الدفع عبر رمز نقطة البيع POS
app.post('/api/pos/pay', authRequired, (req, res) => {
  try {
    const posCode = String(req.body.pos_code || '').trim().toUpperCase();
    const amount = Number(req.body.amount);
    const note = String(req.body.note || 'دفع نقطة بيع POS').trim();

    if (!posCode || !Number.isFinite(amount) || amount <= 0) {
      return res.status(400).json({ ok: false, error: 'يرجى إدخال رمز نقطة البيع والمبلغ' });
    }

    const merchant = db.prepare('SELECT * FROM users WHERE pos_code = ?').get(posCode);
    if (!merchant || merchant.status === 'frozen') {
      return res.status(404).json({ ok: false, error: 'رمز نقطة البيع POS غير صحيح' });
    }
    if (merchant.id === req.user.id) {
      return res.status(400).json({ ok: false, error: 'لا يمكن الدفع لنقطة البيع الخاصة بك' });
    }

    const payerWallet = getUserWalletAccount(req.user.id);
    const merchantWallet = getUserWalletAccount(merchant.id);

    const result = executeDoubleEntry({
      txType: 'pos_payment',
      fromAccountId: payerWallet.id,
      toAccountId: merchantWallet.id,
      amount,
      fee: 0,
      note: `${note} [${posCode}]`
    });

    res.json({
      ok: true,
      transaction: result,
      merchant_name: merchant.full_name,
      balance: getUserWalletAccount(req.user.id).balance
    });
  } catch (err) {
    res.status(400).json({ ok: false, error: err.message });
  }
});

// تقديم طلب توثيق الهوية KYC
app.post('/api/kyc/submit', authRequired, (req, res) => {
  try {
    const idNumber = String(req.body.id_number || '').trim();
    const notes = String(req.body.notes || '').trim();

    if (!idNumber) {
      return res.status(400).json({ ok: false, error: 'يرجى إدخال رقم الهوية أو الوثيقة' });
    }

    db.prepare(`
      UPDATE users
      SET kyc_status = 'pending', kyc_id_number = ?, kyc_notes = ?
      WHERE id = ?
    `).run(idNumber, notes, req.user.id);

    res.json({ ok: true, kyc_status: 'pending', message: 'تم إرسال طلب التوثيق للمراجعة الإدارية' });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// --- مسارات الإدارة العليا (محصورة بـ 783553915 بعد OTP) ---

// لوحة الإحصاءات والمستخدمين والعمليات
app.get('/api/admin/overview', authRequired, adminRequired, (req, res) => {
  const users = db.prepare(`
    SELECT u.id, u.phone, u.full_name, u.role, u.is_merchant, u.pos_code,
           u.kyc_status, u.kyc_id_number, u.kyc_notes, u.daily_limit, u.monthly_limit,
           u.status, u.created_at, COALESCE(a.balance, 0) AS balance
    FROM users u
    LEFT JOIN accounts a ON a.user_id = u.id
    ORDER BY u.id DESC
  `).all();

  const transactions = db.prepare(`
    SELECT t.*,
      fa.account_code AS from_code,
      ta.account_code AS to_code
    FROM transactions t
    LEFT JOIN accounts fa ON t.from_account_id = fa.id
    LEFT JOIN accounts ta ON t.to_account_id = ta.id
    ORDER BY t.id DESC LIMIT 100
  `).all();

  const vault = getSystemAccount('SYS-VAULT-MAIN');
  const totalWalletBalances = db.prepare(`
    SELECT COALESCE(SUM(balance), 0) AS total FROM accounts WHERE account_type = 'wallet'
  `).get().total;

  res.json({
    ok: true,
    stats: {
      users_count: users.length,
      total_wallet_balances: Number(totalWalletBalances),
      vault_balance: vault ? Number(vault.balance) : 0,
      transactions_count: transactions.length
    },
    users,
    transactions
  });
});

// تعديل رصيد حساب (إيداع / خصم إداري) بقيد مزدوج
app.post('/api/admin/adjust-balance', authRequired, adminRequired, (req, res) => {
  try {
    const phone = String(req.body.phone || '').trim();
    const mode = String(req.body.mode || 'credit'); // 'credit' | 'debit'
    const amount = Number(req.body.amount);
    const note = String(req.body.note || 'تسوية رصيد إدارية').trim();

    if (!phone || !Number.isFinite(amount) || amount <= 0) {
      return res.status(400).json({ ok: false, error: 'يرجى تحديد رقم الحساب ومبلغ صحيح' });
    }

    const targetUser = db.prepare('SELECT * FROM users WHERE phone = ?').get(phone);
    if (!targetUser) {
      return res.status(404).json({ ok: false, error: 'الحساب المستهدف غير موجود' });
    }

    const targetWallet = getUserWalletAccount(targetUser.id);
    const vaultAcc = getSystemAccount('SYS-VAULT-MAIN');

    const tx = mode === 'debit'
      ? executeDoubleEntry({
          txType: 'admin_adjust',
          fromAccountId: targetWallet.id,
          toAccountId: vaultAcc ? vaultAcc.id : null,
          amount,
          fee: 0,
          note: `خصم إداري: ${note}`,
          createdByAdmin: 1
        })
      : executeDoubleEntry({
          txType: 'admin_adjust',
          fromAccountId: vaultAcc ? vaultAcc.id : null,
          toAccountId: targetWallet.id,
          amount,
          fee: 0,
          note: `إيداع إداري: ${note}`,
          createdByAdmin: 1
        });

    res.json({
      ok: true,
      transaction: tx,
      new_balance: getUserWalletAccount(targetUser.id).balance
    });
  } catch (err) {
    res.status(400).json({ ok: false, error: err.message });
  }
});

// مراجعة وتحديث حالة التوثيق KYC والحدود وتجميد/تفعيل الحساب
app.post('/api/admin/update-user', authRequired, adminRequired, (req, res) => {
  try {
    const userId = Number(req.body.user_id);
    const kycStatus = req.body.kyc_status;
    const status = req.body.status;
    const dailyLimit = req.body.daily_limit !== undefined ? Number(req.body.daily_limit) : undefined;
    const monthlyLimit = req.body.monthly_limit !== undefined ? Number(req.body.monthly_limit) : undefined;

    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
    if (!user) {
      return res.status(404).json({ ok: false, error: 'المستخدم غير موجود' });
    }

    const nextKyc = ['unverified', 'pending', 'verified', 'rejected'].includes(kycStatus)
      ? kycStatus
      : user.kyc_status;

    let nextStatus = ['active', 'frozen'].includes(status) ? status : user.status;
    if (user.phone === ADMIN_PHONE) {
      nextStatus = 'active';
    }

    const nextDaily = Number.isFinite(dailyLimit) && dailyLimit >= 0 ? dailyLimit : user.daily_limit;
    const nextMonthly = Number.isFinite(monthlyLimit) && monthlyLimit >= 0 ? monthlyLimit : user.monthly_limit;

    db.prepare(`
      UPDATE users
      SET kyc_status = ?, status = ?, daily_limit = ?, monthly_limit = ?
      WHERE id = ?
    `).run(nextKyc, nextStatus, nextDaily, nextMonthly, userId);

    res.json({ ok: true, message: 'تم تحديث بيانات المستخدم بنجاح' });
  } catch (err) {
    res.status(400).json({ ok: false, error: err.message });
  }
});

// إرجاع الواجهة الرئيسية لأي مسار غير API
app.get('*', (req, res) => {
  const indexFile = path.join(__dirname, 'public', 'index.html');
  if (fs.existsSync(indexFile)) {
    return res.sendFile(indexFile);
  }
  res.status(200).send('Al-Barq Wallet API is running. Please add public/index.html.');
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Al-Barq Wallet server running on port ${PORT}`);
});
