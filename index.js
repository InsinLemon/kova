const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const dotenv = require('dotenv');
const multer = require('multer');
const Tesseract = require('tesseract.js');
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const FormData = require('form-data');

// Load environment variables
dotenv.config();

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('../frontend'));

// Database connection
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'cpanel.ecomm.ng',
  user: process.env.DB_USER || 'ecommng1_enoch',
  password: process.env.DB_PASSWORD || 'Enoch@0330',
  database: process.env.DB_NAME || 'ecommng1_kova-app',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

console.log('Database configuration:', {
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  database: process.env.DB_NAME || 'kova-app'
});

// Test database connection
pool.getConnection()
  .then(connection => {
    console.log('Database connected successfully');
    connection.release();
  })
  .catch(err => {
    console.error('Unable to connect to the database:', err);
  });

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret';
console.log('JWT_SECRET:', JWT_SECRET ? 'Set' : 'Not set');

const ADMIN_CREDENTIALS = {
  username: 'admin',
  // bcrypt hash for "Enoch@0330"
  passwordHash: '$2a$10$N9qo8uLOickgx2ZMRZoMy.MrYVJY8sQ7Q3JxW5qP6D2lJ1VvqJQ1W'
};
// Authentication middleware
const auth = async (req, res, next) => {
  try {
    console.log('Auth middleware called for path:', req.path);
    const token = req.header('Authorization')?.replace('Bearer ', '');
    console.log('Headers:', req.headers);
    console.log('Token received:', token ? 'Present' : 'Missing');
    
    if (!token) {
      console.log('No token found in headers');
      return res.status(401).json({ message: 'No authentication token' });
    }
    
    const decoded = jwt.verify(token, JWT_SECRET);
    console.log('Decoded token:', decoded);
    
    // Verify user exists in database
    const [users] = await pool.query('SELECT id FROM users WHERE id = ?', [decoded.id]);
    if (users.length === 0) {
      return res.status(401).json({ message: 'User not found' });
    }
    
    req.user = decoded;
    next();
  } catch (error) {
    console.error('Auth error:', error);
    res.status(401).json({ message: 'Token is invalid or expired' });
  }
};

// Helper function to upload file to PHP endpoint
async function uploadFileToPHP(file) {
  try {
    const formData = new FormData();
    formData.append('image', fs.createReadStream(file.path), {
      filename: path.basename(file.path),
      contentType: file.mimetype
    });

    const length = await new Promise((resolve, reject) => {
      formData.getLength((err, length) => {
        if (err) reject(err);
        else resolve(length);
      });
    });

    const response = await axios.post('https://ecomm.ng/kova-app/upload.php', formData, {
      headers: {
        ...formData.getHeaders(),
        'Content-Length': length
      }
    });

    fs.unlinkSync(file.path);

    if (response.data.success) {
      return response.data.imageUrl;
    } else {
      throw new Error(response.data.error || 'Upload failed');
    }
  } catch (error) {
    if (file?.path && fs.existsSync(file.path)) {
      fs.unlinkSync(file.path);
    }
    throw error;
  }
}

// Configure multer for temporary file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = 'temp_uploads/';
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, 'temp-' + uniqueSuffix + ext);
  }
});

const upload = multer({ 
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB limit
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed (JPEG, PNG, GIF)'), false);
    }
  }
});

// Debug all registered routes
app._router.stack.forEach((r) => {
  if (r.route && r.route.path) {
    console.log(`Registered route: ${r.route.path}`);
  }
});

// ======================
// ROUTES
// ======================

function generateReferralCode(userId) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code = '';
  
  // Start with user ID (padded to 3 digits)
  code += String(userId).padStart(3, '0');
  
  // Add random characters
  for (let i = 0; i < 4; i++) {
    code += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  
  return code;
}

// Admin authentication middleware
const adminAuth = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({ message: 'No authentication token' });
    }
    
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Verify it's the admin user
    if (decoded.username !== ADMIN_CREDENTIALS.username) {
      return res.status(401).json({ message: 'Not authorized as admin' });
    }
    
    req.user = decoded;
    next();
  } catch (error) {
    console.error('Admin auth error:', error);
    res.status(401).json({ message: 'Token is invalid or expired' });
  }
};
// Admin routes
// Admin login endpoint
app.post('/api/admin/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ message: 'Username and password are required' });
    }

    // Check credentials
    if (username !== ADMIN_CREDENTIALS.username) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Compare password with hash
 

    // Create JWT token
    const token = jwt.sign(
      { username: ADMIN_CREDENTIALS.username, role: 'admin' },
      JWT_SECRET,
      { expiresIn: '8h' }
    );

    res.json({ 
      token,
      user: {
        username: ADMIN_CREDENTIALS.username,
        role: 'admin'
      }
    });

  } catch (error) {
    console.error('Admin login error:', error);
    res.status(500).json({ message: 'Server error during login' });
  }
});

app.get('/api/admin/stats', adminAuth, async (req, res) => {
  try {
    const [totalMembers] = await pool.query('SELECT COUNT(*) as count FROM users');
    const [pendingVerifications] = await pool.query('SELECT COUNT(*) as count FROM users WHERE verified = 0');
    const [activeTasks] = await pool.query('SELECT COUNT(*) as count FROM tasks WHERE status = "active"');
    const [pendingWithdrawals] = await pool.query('SELECT COUNT(*) as count FROM withdrawal_requests WHERE status = "pending"');
    
    res.json({
      totalMembers: totalMembers[0].count,
      pendingVerifications: pendingVerifications[0].count,
      activeTasks: activeTasks[0].count,
      pendingWithdrawals: pendingWithdrawals[0].count
    });
  } catch (error) {
    console.error('Admin stats error:', error);
    res.status(500).json({ message: 'Error fetching admin stats' });
  }
});

app.get('/api/admin/activity', adminAuth, async (req, res) => {
  try {
    const [transactions] = await pool.query(`
      SELECT t.id, t.type, t.amount, t.description, t.status, t.created_at, 
             u.name as userName, u.email as userEmail
      FROM transactions t
      LEFT JOIN users u ON t.user_id = u.id
      ORDER BY t.created_at DESC
      LIMIT 10
    `);
    
    res.json(transactions);
  } catch (error) {
    console.error('Admin activity error:', error);
    res.status(500).json({ message: 'Error fetching recent activity' });
  }
});

app.get('/api/admin/members', adminAuth, async (req, res) => {
  try {
    const [members] = await pool.query(`
      SELECT u.*, 
             (SELECT name FROM users WHERE id = u.referred_by) as referred_by_name
      FROM users u
      ORDER BY u.created_at DESC
    `);
    
    res.json(members);
  } catch (error) {
    console.error('Admin members error:', error);
    res.status(500).json({ message: 'Error fetching members' });
  }
});

app.get('/api/admin/members/:id', adminAuth, async (req, res) => {
  try {
    const [members] = await pool.query(`
      SELECT u.*, 
             (SELECT name FROM users WHERE id = u.referred_by) as referred_by_name
      FROM users u
      WHERE u.id = ?
    `, [req.params.id]);
    
    if (members.length === 0) {
      return res.status(404).json({ message: 'Member not found' });
    }
    
    res.json(members[0]);
  } catch (error) {
    console.error('Admin member details error:', error);
    res.status(500).json({ message: 'Error fetching member details' });
  }
});

app.post('/api/admin/members/:id/approve', adminAuth, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    await connection.beginTransaction();
    
    try {
      // Verify user
      await connection.query(
        'UPDATE users SET verified = 1 WHERE id = ?', 
        [req.params.id]
      );
      
      // Process any pending referral payments
      const [referralPayments] = await connection.query(
        `SELECT rp.id, rp.referrer_id, rp.amount 
         FROM referral_payments rp
         JOIN users u ON rp.referred_id = u.id
         WHERE rp.referred_id = ? AND rp.status = 'pending' AND u.verified = 1`,
        [req.params.id]
      );

      for (const payment of referralPayments) {
        // Credit referrer
        await connection.query(
          `UPDATE users 
           SET wallet_balance = wallet_balance + ?, earnings = earnings + ?
           WHERE id = ?`,
          [payment.amount, payment.amount, payment.referrer_id]
        );

        // Credit referred user (bonus)
        await connection.query(
          `UPDATE users 
           SET wallet_balance = wallet_balance + 500.00, earnings = earnings + 500.00
           WHERE id = ?`,
          [req.params.id]
        );

        // Mark payment as paid
        await connection.query(
          `UPDATE referral_payments 
           SET status = 'paid', paid_at = NOW()
           WHERE id = ?`,
          [payment.id]
        );

        // Create transaction records
        await connection.query(
          `INSERT INTO transactions 
          (user_id, type, amount, description, status, created_at)
          VALUES (?, 'referral_bonus', ?, 'Referral bonus for user #${req.params.id}', 'completed', NOW())`,
          [payment.referrer_id, payment.amount]
        );

        await connection.query(
          `INSERT INTO transactions 
          (user_id, type, amount, description, status, created_at)
          VALUES (?, 'referral_bonus', 500.00, 'Referral signup bonus', 'completed', NOW())`,
          [req.params.id]
        );
      }
      
      await connection.commit();
      
      res.json({ success: true, message: 'Member approved successfully' });
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Admin approve member error:', error);
    res.status(500).json({ message: 'Error approving member' });
  }
});

app.post('/api/admin/members/:id/reject', adminAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM users WHERE id = ?', [req.params.id]);
    res.json({ success: true, message: 'Member rejected and removed' });
  } catch (error) {
    console.error('Admin reject member error:', error);
    res.status(500).json({ message: 'Error rejecting member' });
  }
});

app.get('/api/admin/tasks', adminAuth, async (req, res) => {
  try {
    const [tasks] = await pool.query(`
      SELECT t.*, u.name as creatorName
      FROM tasks t
      JOIN users u ON t.created_by = u.id
      ORDER BY t.created_at DESC
    `);
    
    res.json(tasks);
  } catch (error) {
    console.error('Admin tasks error:', error);
    res.status(500).json({ message: 'Error fetching tasks' });
  }
});

app.get('/api/admin/tasks/:id', adminAuth, async (req, res) => {
  try {
    const [tasks] = await pool.query(`
      SELECT t.*, u.name as creatorName
      FROM tasks t
      JOIN users u ON t.created_by = u.id
      WHERE t.id = ?
    `, [req.params.id]);
    
    if (tasks.length === 0) {
      return res.status(404).json({ message: 'Task not found' });
    }
    
    res.json(tasks[0]);
  } catch (error) {
    console.error('Admin task details error:', error);
    res.status(500).json({ message: 'Error fetching task details' });
  }
});

app.post('/api/admin/tasks/:id/approve', adminAuth, async (req, res) => {
  try {
    await pool.query(
      `UPDATE tasks 
       SET status = 'active', payment_status = 'verified'
       WHERE id = ?`,
      [req.params.id]
    );
    
    res.json({ success: true, message: 'Task approved successfully' });
  } catch (error) {
    console.error('Admin approve task error:', error);
    res.status(500).json({ message: 'Error approving task' });
  }
});

app.post('/api/admin/tasks/:id/reject', adminAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM tasks WHERE id = ?', [req.params.id]);
    res.json({ success: true, message: 'Task rejected and removed' });
  } catch (error) {
    console.error('Admin reject task error:', error);
    res.status(500).json({ message: 'Error rejecting task' });
  }
});

app.get('/api/admin/withdrawals', adminAuth, async (req, res) => {
  try {
    const [withdrawals] = await pool.query(`
      SELECT w.*, u.name as userName
      FROM withdrawal_requests w
      JOIN users u ON w.user_id = u.id
      ORDER BY w.created_at DESC
    `);
    
    res.json(withdrawals);
  } catch (error) {
    console.error('Admin withdrawals error:', error);
    res.status(500).json({ message: 'Error fetching withdrawals' });
  }
});

app.get('/api/admin/withdrawals/:id', adminAuth, async (req, res) => {
  try {
    const [withdrawals] = await pool.query(`
      SELECT w.*, u.name as userName
      FROM withdrawal_requests w
      JOIN users u ON w.user_id = u.id
      WHERE w.id = ?
    `, [req.params.id]);
    
    if (withdrawals.length === 0) {
      return res.status(404).json({ message: 'Withdrawal not found' });
    }
    
    res.json(withdrawals[0]);
  } catch (error) {
    console.error('Admin withdrawal details error:', error);
    res.status(500).json({ message: 'Error fetching withdrawal details' });
  }
});

app.post('/api/admin/withdrawals/:id/approve', adminAuth, async (req, res) => {
  try {
    await pool.query(
      `UPDATE withdrawal_requests 
       SET status = 'processed', processed_at = NOW()
       WHERE id = ?`,
      [req.params.id]
    );
    
    res.json({ success: true, message: 'Withdrawal marked as sent' });
  } catch (error) {
    console.error('Admin approve withdrawal error:', error);
    res.status(500).json({ message: 'Error approving withdrawal' });
  }
});

app.post('/api/admin/withdrawals/:id/reject', adminAuth, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    await connection.beginTransaction();
    
    try {
      // Get withdrawal details
      const [withdrawals] = await connection.query(
        'SELECT * FROM withdrawal_requests WHERE id = ?',
        [req.params.id]
      );
      
      if (withdrawals.length === 0) {
        await connection.rollback();
        return res.status(404).json({ message: 'Withdrawal not found' });
      }
      
      const withdrawal = withdrawals[0];
      
      // Return funds to user
      await connection.query(
        `UPDATE users 
         SET wallet_balance = wallet_balance + ?
         WHERE id = ?`,
        [withdrawal.amount, withdrawal.user_id]
      );
      
      // Update withdrawal status
      await connection.query(
        `UPDATE withdrawal_requests 
         SET status = 'rejected', processed_at = NOW()
         WHERE id = ?`,
        [req.params.id]
      );
      
      // Update transaction status
      await connection.query(
        `UPDATE transactions 
         SET status = 'failed', description = CONCAT(description, ' - Rejected by admin')
         WHERE description LIKE ? AND type = 'withdrawal'`,
        [`%Withdrawal request #${req.params.id}%`]
      );
      
      await connection.commit();
      
      res.json({ success: true, message: 'Withdrawal rejected and funds returned' });
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Admin reject withdrawal error:', error);
    res.status(500).json({ message: 'Error rejecting withdrawal' });
  }
});

app.get('/api/admin/pending-tasks', adminAuth, async (req, res) => {
  try {
    const [pendingTasks] = await pool.query(`
      SELECT pt.*, t.title as taskTitle, u.name as userName
      FROM pending_tasks pt
      JOIN tasks t ON pt.task_id = t.id
      JOIN users u ON pt.user_id = u.id
      WHERE pt.status = 'pending'
      ORDER BY pt.submitted_at DESC
    `);
    
    res.json(pendingTasks);
  } catch (error) {
    console.error('Admin pending tasks error:', error);
    res.status(500).json({ message: 'Error fetching pending tasks' });
  }
});

app.get('/api/admin/pending-tasks/:id', adminAuth, async (req, res) => {
  try {
    const [pendingTasks] = await pool.query(`
      SELECT pt.*, t.title as taskTitle, u.name as userName
      FROM pending_tasks pt
      JOIN tasks t ON pt.task_id = t.id
      JOIN users u ON pt.user_id = u.id
      WHERE pt.id = ?
    `, [req.params.id]);
    
    if (pendingTasks.length === 0) {
      return res.status(404).json({ message: 'Pending task not found' });
    }
    
    res.json(pendingTasks[0]);
  } catch (error) {
    console.error('Admin pending task details error:', error);
    res.status(500).json({ message: 'Error fetching pending task details' });
  }
});

app.post('/api/admin/pending-tasks/:id/approve', adminAuth, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    await connection.beginTransaction();
    
    try {
      // Get pending task details
      const [pendingTasks] = await connection.query(
        `SELECT pt.*, t.cost_per_participant
         FROM pending_tasks pt
         JOIN tasks t ON pt.task_id = t.id
         WHERE pt.id = ?`,
        [req.params.id]
      );
      
      if (pendingTasks.length === 0) {
        await connection.rollback();
        return res.status(404).json({ message: 'Pending task not found' });
      }
      
      const pendingTask = pendingTasks[0];
      
      // Update pending task status
      await connection.query(
        `UPDATE pending_tasks 
         SET status = 'approved', processed_at = NOW()
         WHERE id = ?`,
        [req.params.id]
      );
      
      // Credit user's wallet
      await connection.query(
        `UPDATE users 
         SET wallet_balance = wallet_balance + ?, earnings = earnings + ?
         WHERE id = ?`,
        [pendingTask.cost_per_participant, pendingTask.cost_per_participant, pendingTask.user_id]
      );
      
      // Create transaction record
      await connection.query(
        `INSERT INTO transactions 
         (user_id, type, amount, description, status, created_at)
         VALUES (?, 'task_completion', ?, 'Payment for completing task #${pendingTask.task_id}', 'completed', NOW())`,
        [pendingTask.user_id, pendingTask.cost_per_participant]
      );
      
      // Mark as completed in user_completed_tasks
      await connection.query(
        `INSERT INTO user_completed_tasks 
         (user_id, task_id, completed_at)
         VALUES (?, ?, NOW())
         ON DUPLICATE KEY UPDATE completed_at = NOW()`,
        [pendingTask.user_id, pendingTask.task_id]
      );
      
      await connection.commit();
      
      res.json({ success: true, message: 'Task submission approved' });
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Admin approve pending task error:', error);
    res.status(500).json({ message: 'Error approving task submission' });
  }
});

app.post('/api/admin/pending-tasks/:id/reject', adminAuth, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    await connection.beginTransaction();
    
    try {
      // Get pending task details
      const [pendingTasks] = await connection.query(
        `SELECT pt.*, t.cost_per_participant
         FROM pending_tasks pt
         JOIN tasks t ON pt.task_id = t.id
         WHERE pt.id = ?`,
        [req.params.id]
      );
      
      if (pendingTasks.length === 0) {
        await connection.rollback();
        return res.status(404).json({ message: 'Pending task not found' });
      }
      
      const pendingTask = pendingTasks[0];
      
      // Update pending task status
      await connection.query(
        `UPDATE pending_tasks 
         SET status = 'rejected', processed_at = NOW()
         WHERE id = ?`,
        [req.params.id]
      );
      
      // Return participant slot to task
      await connection.query(
        `UPDATE tasks 
         SET participants_count = participants_count + 1
         WHERE id = ?`,
        [pendingTask.task_id]
      );
      
      // Remove pending balance from user
      await connection.query(
        `UPDATE users 
         SET pending_balance = pending_balance - ?
         WHERE id = ?`,
        [pendingTask.cost_per_participant, pendingTask.user_id]
      );
      
      await connection.commit();
      
      res.json({ success: true, message: 'Task submission rejected' });
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Admin reject pending task error:', error);
    res.status(500).json({ message: 'Error rejecting task submission' });
  }
});

// 1. Authentication Routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, user_type, phone, website, referral_code } = req.body;
    
    if (!name || !email || !password || !user_type) {
      return res.status(400).json({ message: 'All required fields must be provided' });
    }
    
    if (!['member', 'influencer', 'business'].includes(user_type)) {
      return res.status(400).json({ message: 'Invalid user type' });
    }
    
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ message: 'Invalid email format' });
    }
    
    if (password.length < 8) {
      return res.status(400).json({ message: 'Password must be at least 8 characters long' });
    }
    
    const [existingUsers] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (existingUsers.length > 0) {
      return res.status(400).json({ message: 'User already exists with this email' });
    }
    
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const verified = user_type !== 'member' ? 1 : 0;
    
    // Start transaction
    const connection = await pool.getConnection();
    await connection.beginTransaction();
    
    try {
      // Insert new user
      const [result] = await connection.query(
        `INSERT INTO users 
        (name, email, password, phone, website, user_type, verified, created_at, updated_at) 
        VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`,
        [name, email, hashedPassword, phone || null, website || null, user_type, verified]
      );
      
      const userId = result.insertId;
      
      // Generate and save referral code
      const referralCode = generateReferralCode(userId);
      await connection.query(
        'UPDATE users SET referral_code = ? WHERE id = ?',
        [referralCode, userId]
      );
      
      // Process referral if code was provided
      let referrerId = null;
if (referral_code) {  // Now this will work since referral_code is defined
    const [referrers] = await connection.query(
        'SELECT id FROM users WHERE referral_code = ?',
        [referral_code]
    );
       
        
        if (referrers.length > 0) {
          referrerId = referrers[0].id;
          await connection.query(
            'UPDATE users SET referred_by = ? WHERE id = ?',
            [referrerId, userId]
          );
          
          // Create pending referral payment (will be paid when user verifies)
          await connection.query(
            `INSERT INTO referral_payments 
            (referrer_id, referred_id, amount, status) 
            VALUES (?, ?, 500.00, 'pending')`,
            [referrerId, userId]
          );
        }
      }
      
      await connection.commit();
      
      const token = jwt.sign({ id: userId, user_type, verified }, JWT_SECRET, { expiresIn: '30d' });
      
      const userData = {
        id: userId,
        name,
        email,
        phone: phone || null,
        website: website || null,
        user_type,
        verified,
        wallet_balance: 0.00,
        earnings: 0.00,
        referral_code: referralCode,
        created_at: new Date()
      };
      
      res.status(201).json({ token, user: userData });
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Server error during registration' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }
    
    const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (users.length === 0) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }
    
    const user = users[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }
    
    const token = jwt.sign(
      { id: user.id, user_type: user.user_type },
      JWT_SECRET,
      { expiresIn: '30d' }
    );
    
    const userData = {
      id: user.id,
      name: user.name,
      email: user.email,
      user_type: user.user_type,
      verified: user.verified,
      wallet_balance: user.wallet_balance,
      earnings: user.earnings,
      created_at: user.created_at
    };
    
    res.json({ token, user: userData });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error during login' });
  }
});

app.get('/api/auth/profile', auth, async (req, res) => {
  try {
    const [users] = await pool.query(
      'SELECT id, name, email, phone, website, user_type, verified, wallet_balance, pending_balance, earnings, referrer_id, referral_code, created_at, updated_at FROM users WHERE id = ?',
      [req.user.id]
    );
    
    if (users.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    res.json(users[0]);
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ message: 'Server error while fetching profile' });
  }
});

// Get user's referral stats
app.get('/api/referrals/stats', auth, async (req, res) => {
  try {
    const [stats] = await pool.query(
      `SELECT 
        COUNT(*) as total_referrals,
        SUM(CASE WHEN u.verified = 1 THEN 1 ELSE 0 END) as verified_referrals,
        COALESCE(SUM(CASE WHEN rp.status = 'paid' THEN rp.amount ELSE 0 END), 0) as total_earnings
       FROM users u
       LEFT JOIN referral_payments rp ON rp.referrer_id = ? AND rp.referred_id = u.id
       WHERE u.referred_by = ?`,
      [req.user.id, req.user.id]
    );

    res.json({
      success: true,
      stats: {
        total_referrals: stats[0]?.total_referrals || 0,
        verified_referrals: stats[0]?.verified_referrals || 0,
        total_earnings: stats[0]?.total_earnings || 0
      }
    });
  } catch (error) {
    console.error('Get referral stats error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Error fetching referral stats' 
    });
  }
});

// Get user's referral list
app.get('/api/referrals', auth, async (req, res) => {
  try {
    const [referrals] = await pool.query(
      `SELECT 
        u.id, u.name, u.email, u.created_at, u.verified,
        rp.amount, rp.status, rp.paid_at
       FROM users u
       LEFT JOIN referral_payments rp ON rp.referred_id = u.id AND rp.referrer_id = ?
       WHERE u.referred_by = ?
       ORDER BY u.created_at DESC`,
      [req.user.id, req.user.id]
    );

    res.json({
      success: true,
      referrals
    });
  } catch (error) {
    console.error('Get referrals error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Error fetching referral list' 
    });
  }
});

app.post('/api/auth/verify-receipt', auth, upload.single('receipt'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ message: 'No receipt file uploaded' });
  }

  try {
    console.log('Starting OCR processing...');
    const imageBuffer = fs.readFileSync(req.file.path);
    
    const { data: { text } } = await Tesseract.recognize(
      imageBuffer,
      'eng',
      { logger: m => console.log(m) }
    );

    console.log('OCR processing completed');
    console.log('Extracted text:', text);

    const requiredName = 'ENOCH TIRENIOLUWA BENSON';
    const requiredBank = 'OPAY DIGITAL SERVICES LIMITED';
    const requiredAmount = 'NGN 1,500.00';
    const normalizedText = text.toUpperCase().replace(/\s+/g, ' ');

    const hasName = normalizedText.includes(requiredName.toUpperCase());
    const hasBank = normalizedText.includes(requiredBank.toUpperCase());
    const hasAmount = normalizedText.includes(requiredAmount.toUpperCase());

    if (!hasName || !hasBank || !hasAmount) {
      fs.unlinkSync(req.file.path);
      return res.status(400).json({ 
        message: 'Verification failed. Receipt must show:\n' +
        '- Recipient: Enoch Tirenioluwa Benson\n' +
        '- Bank: Opay Digital Services Limited\n' +
        '- Amount: NGN 1,500.00'
      });
    }

    // Remove the early return statement that was here
    fs.unlinkSync(req.file.path);

    const connection = await pool.getConnection();
    await connection.beginTransaction();

    try {
      // Verify user
      await connection.query(
        'UPDATE users SET verified = 1 WHERE id = ?', 
        [req.user.id]
      );

      // Process any pending referral payments
      const [referralPayments] = await connection.query(
        `SELECT rp.id, rp.referrer_id, rp.amount 
         FROM referral_payments rp
         JOIN users u ON rp.referred_id = u.id
         WHERE rp.referred_id = ? AND rp.status = 'pending' AND u.verified = 1`,
        [req.user.id]
      );

      for (const payment of referralPayments) {
        // Credit referrer
        await connection.query(
          `UPDATE users 
           SET wallet_balance = wallet_balance + ?, earnings = earnings + ?
           WHERE id = ?`,
          [payment.amount, payment.amount, payment.referrer_id]
        );

        // Credit referred user (bonus)
        await connection.query(
          `UPDATE users 
           SET wallet_balance = wallet_balance + 500.00, earnings = earnings + 500.00
           WHERE id = ?`,
          [req.user.id]
        );

        // Mark payment as paid
        await connection.query(
          `UPDATE referral_payments 
           SET status = 'paid', paid_at = NOW()
           WHERE id = ?`,
          [payment.id]
        );

        // Create transaction records
        await connection.query(
          `INSERT INTO transactions 
          (user_id, type, amount, description, status, created_at)
          VALUES (?, 'referral_bonus', ?, 'Referral bonus for user #${req.user.id}', 'completed', NOW())`,
          [payment.referrer_id, payment.amount]
        );

        await connection.query(
          `INSERT INTO transactions 
          (user_id, type, amount, description, status, created_at)
          VALUES (?, 'referral_bonus', 500.00, 'Referral signup bonus', 'completed', NOW())`,
          [req.user.id]
        );
      }

      await connection.commit();

      return res.json({ 
        success: true,
        message: 'Receipt verified successfully!'
      });
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Error:', error);
    if (req.file?.path) fs.unlinkSync(req.file.path);
    return res.status(500).json({ 
      message: 'Error processing receipt. Please try again.' 
    });
  }
});
// 2. WhatsApp Task Routes
app.get('/api/tasks/whatsapp-status', auth, async (req, res) => {
  try {
    const [tasks] = await pool.query(
      `SELECT id, title, description, platform, action, participants_count, 
       cost_per_participant, total_cost, status, payment_status, created_at 
       FROM tasks 
       WHERE created_by = ? AND platform = 'whatsapp' AND action = 'status'
       ORDER BY created_at DESC`,
      [req.user.id]
    );
    
    res.json(tasks);
  } catch (error) {
    console.error('Get WhatsApp tasks error:', error);
    res.status(500).json({ message: 'Error fetching WhatsApp status tasks' });
  }
});

app.get('/api/tasks/whatsapp-status/:id/submissions', auth, async (req, res) => {
  try {
    const taskId = req.params.id;
    
    // Verify task belongs to user
    const [tasks] = await pool.query(
      `SELECT id FROM tasks 
       WHERE id = ? AND created_by = ? AND platform = 'whatsapp' AND action = 'status'`,
      [taskId, req.user.id]
    );
    
    if (tasks.length === 0) {
      return res.status(404).json({ message: 'Task not found or not authorized' });
    }
    
    // Get submissions
    const [submissions] = await pool.query(
      `SELECT pt.id, pt.description, pt.profile_link, pt.phone_number, pt.status, 
              pt.submitted_at, pt.processed_at, u.name as user_name, u.email as user_email
       FROM pending_tasks pt
       JOIN users u ON pt.user_id = u.id
       WHERE pt.task_id = ?`,
      [taskId]
    );
    
    res.json(submissions);
  } catch (error) {
    console.error('Get WhatsApp submissions error:', error);
    res.status(500).json({ message: 'Error fetching WhatsApp status submissions' });
  }
});

// 3. Task Submission Routes
app.post('/api/tasks/:id/submit', auth, upload.single('proof'), async (req, res) => {
  try {
    const taskId = req.params.id;
    const userId = req.user.id;
    
    const [tasks] = await pool.query(
      'SELECT * FROM tasks WHERE id = ? AND status = "active" AND payment_status = "verified" AND participants_count > 0',
      [taskId]
    );
    
    if (tasks.length === 0) {
      if (req.file) fs.unlinkSync(req.file.path);
      return res.status(404).json({ message: 'Task not found or not available' });
    }
    
    const task = tasks[0];
    const [existingSubmissions] = await pool.query(
      'SELECT * FROM pending_tasks WHERE task_id = ? AND user_id = ?',
      [taskId, userId]
    );
    
    if (existingSubmissions.length > 0) {
      if (req.file) fs.unlinkSync(req.file.path);
      return res.status(400).json({ message: 'You have already submitted this task' });
    }
    
    let proofUrl = null;
    if (req.file) {
      try {
        proofUrl = await uploadFileToPHP(req.file);
      } catch (uploadError) {
        console.error('Upload error:', uploadError);
        return res.status(500).json({ message: 'Failed to upload proof image' });
      }
    }
    
    const connection = await pool.getConnection();
    await connection.beginTransaction();
    
    try {
      await connection.query(
        `INSERT INTO pending_tasks 
        (task_id, user_id, description, profile_link, social_handle, phone_number, proof, status, submitted_at) 
        VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', NOW())`,
        [
          taskId,
          userId,
          req.body.description,
          req.body.profile_link,
          req.body.social_handle,
          req.body.phone_number,
          proofUrl
        ]
      );
      
      await connection.query(
        `UPDATE users 
        SET pending_balance = pending_balance + ?
        WHERE id = ?`,
        [task.cost_per_participant, userId]
      );
      
      await connection.query(
        'UPDATE tasks SET participants_count = participants_count - 1 WHERE id = ? AND participants_count > 0',
        [taskId]
      );
      
      await connection.commit();
      
      res.status(201).json({
        success: true,
        message: 'Task submitted successfully',
        pending_balance: task.cost_per_participant
      });
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Task submission error:', error);
    res.status(500).json({ message: 'Error submitting task' });
  }
});

app.get('/api/tasks/pending', auth, async (req, res) => {
  try {
    console.log('Fetching pending tasks for user ID:', req.user.id);
    
    const [pendingTasks] = await pool.query(
      `SELECT t.id, t.title, t.description, t.platform, t.cost_per_participant, 
              t.profile_link, t.action, pt.status as submission_status, pt.submitted_at
       FROM pending_tasks pt
       INNER JOIN tasks t ON pt.task_id = t.id
       WHERE pt.user_id = ? AND pt.status = 'pending'`,
      [req.user.id]
    );
    
    res.json(pendingTasks || []);
  } catch (error) {
    console.error('Error fetching pending tasks:', error);
    res.json([]);
  }
});

// 4. Task Management Routes
app.get('/api/tasks/:id/submissions', auth, async (req, res) => {
  try {
    const taskId = req.params.id;
    
    const [tasks] = await pool.query(
      'SELECT id FROM tasks WHERE id = ? AND created_by = ?',
      [taskId, req.user.id]
    );
    
    if (tasks.length === 0) {
      return res.status(404).json({ message: 'Task not found or not authorized' });
    }
    
    const [submissions] = await pool.query(
      `SELECT pt.*, u.name as user_name, u.email as user_email 
       FROM pending_tasks pt
       JOIN users u ON pt.user_id = u.id
       WHERE pt.task_id = ? AND pt.status = 'pending'`,
      [taskId]
    );
    
    res.json(submissions);
  } catch (error) {
    console.error('Get submissions error:', error);
    res.status(500).json({ message: 'Server error while fetching submissions' });
  }
});

app.post('/api/submissions/:id/review', auth, async (req, res) => {
  try {
    const submissionId = req.params.id;
    const { action } = req.body;
    
    if (!['approved', 'rejected'].includes(action)) {
      return res.status(400).json({ message: 'Invalid action' });
    }
    
    const [submissions] = await pool.query(
      `SELECT pt.*, t.created_by as task_owner, t.cost_per_participant 
       FROM pending_tasks pt
       JOIN tasks t ON pt.task_id = t.id
       WHERE pt.id = ?`,
      [submissionId]
    );
    
    if (submissions.length === 0) {
      return res.status(404).json({ message: 'Submission not found' });
    }
    
    const submission = submissions[0];
    
    if (submission.task_owner !== req.user.id) {
      return res.status(403).json({ message: 'Not authorized to review this submission' });
    }
    
    const connection = await pool.getConnection();
    await connection.beginTransaction();
    
    try {
      await connection.query(
        `UPDATE pending_tasks 
         SET status = ?, processed_at = NOW()
         WHERE id = ?`,
        [action, submissionId]
      );
      
      if (action === 'approved') {
        await connection.query(
          `UPDATE users 
           SET pending_balance = pending_balance - ?,
               wallet_balance = wallet_balance + ?,
               earnings = earnings + ?
           WHERE id = ?`,
          [submission.cost_per_participant, submission.cost_per_participant, 
           submission.cost_per_participant, submission.user_id]
        );
        
        await connection.query(
          `INSERT INTO transactions 
           (user_id, type, amount, description, status, created_at)
           VALUES (?, 'task_completion', ?, 'Payment for completing task #${submission.task_id}', 'completed', NOW())`,
          [submission.user_id, submission.cost_per_participant]
        );
        
        await connection.query(
          `UPDATE user_tasks 
           SET status = 'completed', completed_at = NOW()
           WHERE user_id = ? AND task_id = ?`,
          [submission.user_id, submission.task_id]
        );
        
        await connection.query(
          `INSERT INTO user_completed_tasks 
           (user_id, task_id, completed_at)
           VALUES (?, ?, NOW())`,
          [submission.user_id, submission.task_id]
        );
      } else {
        await connection.query(
          `UPDATE users 
           SET pending_balance = pending_balance - ?
           WHERE id = ?`,
          [submission.cost_per_participant, submission.user_id]
        );
      }
      
      await connection.commit();
      
      res.json({ 
        success: true,
        message: `Submission ${action} successfully`
      });
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Submission review error:', error);
    res.status(500).json({ message: 'Server error while reviewing submission' });
  }
});

// 5. Task Creation with PHP Upload
app.post('/api/tasks', auth, upload.single('content'), async (req, res) => {
  try {
    const { title, description, platform, action, participants_count, cost_per_participant } = req.body;
    const created_by = req.user.id;

    // Validate required fields
    if (!title || !description || !platform || !action || !participants_count || !cost_per_participant) {
      if (req.file) fs.unlinkSync(req.file.path);
      return res.status(400).json({ message: 'All required fields must be provided' });
    }

    // Validate image file
    if (!req.file) {
      return res.status(400).json({ message: 'Image file is required' });
    }

    let contentUrl = null;
    try {
      contentUrl = await uploadFileToPHP(req.file);
    } catch (uploadError) {
      console.error('Upload error:', uploadError);
      return res.status(500).json({ message: 'Failed to upload content image' });
    }

    const total_cost = participants_count * cost_per_participant;

    const [result] = await pool.query(
      `INSERT INTO tasks 
      (title, description, platform, action, participants_count, 
       cost_per_participant, total_cost, created_by, status, payment_status, created_at, updated_at, content_path)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', 'pending', NOW(), NOW(), ?)`,
      [
        title,
        description,
        platform,
        action,
        participants_count,
        cost_per_participant,
        total_cost,
        created_by,
        contentUrl
      ]
    );

    res.status(201).json({
      id: result.insertId,
      message: 'Task created successfully. Please verify payment to activate it.',
      content_path: contentUrl
    });
  } catch (error) {
    console.error('Create task error:', error);
    res.status(500).json({ message: 'Server error while creating task' });
  }
});

// 6. Influencer Task Creation
app.post('/api/influencer-tasks', auth, async (req, res) => {
  try {
    const { 
      title, 
      description, 
      platform, 
      action, 
      participants_count, 
      cost_per_participant,
      profile_link 
    } = req.body;
    
    const created_by = req.user.id;

    // Validate required fields
    if (!title || !description || !platform || !action || !participants_count || !cost_per_participant || !profile_link) {
      return res.status(400).json({ message: 'All required fields must be provided' });
    }

    const total_cost = participants_count * cost_per_participant;

    const [result] = await pool.query(
      `INSERT INTO tasks 
      (title, description, platform, action, participants_count, 
       cost_per_participant, total_cost, created_by, status, payment_status, 
       created_at, updated_at, profile_link)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', 'pending', NOW(), NOW(), ?)`,
      [
        title,
        description,
        platform,
        action,
        participants_count,
        cost_per_participant,
        total_cost,
        created_by,
        profile_link
      ]
    );

    res.status(201).json({
      id: result.insertId,
      message: 'Influencer task created successfully. Please verify payment to activate it.'
    });
  } catch (error) {
    console.error('Create influencer task error:', error);
    res.status(500).json({ message: 'Server error while creating influencer task' });
  }
});

app.get('/api/tasks/stats', auth, async (req, res) => {
  try {
    const userId = req.user.id;
    const userType = req.user.user_type;
    
    if (userType === 'business') {
      // For business users - only show WhatsApp status tasks
      const [tasks] = await pool.query(
        `SELECT * FROM tasks 
         WHERE created_by = ? AND platform = 'whatsapp' AND action = 'status'`,
        [userId]
      );

      // Calculate statistics for business
      const stats = await calculateBusinessStats(userId, tasks);
      return res.json({ success: true, stats });

    } else if (userType === 'influencer') {
      // For influencer users - only show social media tasks (not WhatsApp status)
      const [tasks] = await pool.query(
        `SELECT * FROM tasks 
         WHERE created_by = ? AND platform != 'whatsapp'`,
        [userId]
      );

      // Calculate statistics for influencer
      const stats = await calculateInfluencerStats(userId, tasks);
      return res.json({ success: true, stats });

    } else {
      // For regular members
      const stats = await calculateMemberStats(userId);
      return res.json({ success: true, stats });
    }
  } catch (error) {
    console.error('Stats endpoint error:', error);
    return res.status(500).json({
      success: false,
      message: "Error calculating statistics"
    });
  }
});

// Influencer-specific calculations (social media only)
async function calculateInfluencerStats(userId, tasks) {
  const [approvedSubmissions] = await pool.query(
    `SELECT COUNT(*) as count 
     FROM pending_tasks 
     WHERE status = 'approved' 
     AND task_id IN (SELECT id FROM tasks WHERE created_by = ? AND platform != 'whatsapp')`,
    [userId]
  );

  const [pendingSubmissions] = await pool.query(
    `SELECT COUNT(*) as count 
     FROM pending_tasks 
     WHERE status = 'pending' 
     AND task_id IN (SELECT id FROM tasks WHERE created_by = ? AND platform != 'whatsapp')`,
    [userId]
  );

  const activeTasks = tasks.filter(task => task.status === 'active').length;
  const pendingTasks = tasks.filter(task => task.status === 'pending').length;
  const totalCost = tasks.reduce((sum, task) => sum + parseFloat(task.total_cost || 0), 0);
  const totalParticipants = tasks.reduce((sum, task) => sum + (task.participants_count || 0), 0);
  const completedTasks = approvedSubmissions[0]?.count || 0;
  const pendingApprovals = pendingSubmissions[0]?.count || 0;
  
  return {
    activeTasks,
    pendingTasks,
    totalCost,
    engagementRate: totalParticipants > 0 ? Math.round((completedTasks / totalParticipants) * 100) : 0,
    estimatedFollowers: completedTasks * 10, // Estimated followers gained
    completedTasks,
    totalParticipants,
    pendingApprovals,
    totalSubmissions: completedTasks + pendingApprovals
  };
}

// Business-specific calculations (WhatsApp status only)
async function calculateBusinessStats(userId, tasks) {
  const [approvedSubmissions] = await pool.query(
    `SELECT COUNT(*) as count 
     FROM pending_tasks 
     WHERE status = 'approved' 
     AND task_id IN (SELECT id FROM tasks WHERE created_by = ? AND platform = 'whatsapp' AND action = 'status')`,
    [userId]
  );

  const activeTasks = tasks.filter(task => task.status === 'active').length;
  const totalCost = tasks.reduce((sum, task) => sum + parseFloat(task.total_cost || 0), 0);
  const totalParticipants = tasks.reduce((sum, task) => sum + (task.participants_count || 0), 0);
  const completedTasks = approvedSubmissions[0]?.count || 0;
  
  return {
    activeTasks,
    totalCost,
    engagementRate: totalParticipants > 0 ? Math.round((completedTasks / totalParticipants) * 100) : 0,
    totalViews: completedTasks * 100, // Estimated views
    completedTasks,
    totalParticipants
  };
}
// Withdrawal request endpoint
app.post('/api/withdrawals', auth, async (req, res) => {
  try {
    const { amount, bank_name, account_number, account_name } = req.body;
    const userId = req.user.id;

    // Validate input
    if (!amount || !bank_name || !account_number || !account_name) {
      return res.status(400).json({ 
        success: false,
        message: 'All fields are required: amount, bank_name, account_number, account_name'
      });
    }

    const withdrawalAmount = parseFloat(amount);
    
    // Validate amount
    if (isNaN(withdrawalAmount)) {
      return res.status(400).json({ 
        success: false,
        message: 'Invalid amount format'
      });
    }

    if (withdrawalAmount < 1000) {
      return res.status(400).json({ 
        success: false,
        message: 'Minimum withdrawal amount is ₦1,000'
      });
    }

    // Get user balance
    const [users] = await pool.query(
      'SELECT wallet_balance FROM users WHERE id = ?',
      [userId]
    );

    if (users.length === 0) {
      return res.status(404).json({ 
        success: false,
        message: 'User not found'
      });
    }

    const user = users[0];
    const currentBalance = parseFloat(user.wallet_balance);

    if (withdrawalAmount > currentBalance) {
      return res.status(400).json({ 
        success: false,
        message: 'Insufficient balance for this withdrawal'
      });
    }

    // Start transaction
    const connection = await pool.getConnection();
    await connection.beginTransaction();

    try {
      // Create withdrawal request
      const [withdrawalResult] = await connection.query(
        `INSERT INTO withdrawal_requests 
        (user_id, amount, bank_name, account_number, account_name, status)
        VALUES (?, ?, ?, ?, ?, 'pending')`,
        [userId, withdrawalAmount, bank_name, account_number, account_name]
      );

      // Deduct from user's balance
      await connection.query(
        'UPDATE users SET wallet_balance = wallet_balance - ? WHERE id = ?',
        [withdrawalAmount, userId]
      );

      // Create transaction record
      await connection.query(
        `INSERT INTO transactions 
        (user_id, type, amount, description, status, created_at)
        VALUES (?, 'withdrawal', ?, 'Withdrawal request #${withdrawalResult.insertId}', 'pending', NOW())`,
        [userId, withdrawalAmount]
      );

      await connection.commit();

      res.status(201).json({
        success: true,
        message: 'Withdrawal request submitted successfully',
        withdrawal_id: withdrawalResult.insertId,
        new_balance: currentBalance - withdrawalAmount
      });
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Withdrawal request error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Error processing withdrawal request'
    });
  }
});

// Get user's withdrawal history
app.get('/api/withdrawals', auth, async (req, res) => {
  try {
    const [withdrawals] = await pool.query(
      `SELECT id, amount, bank_name, account_number, account_name, 
       status, created_at, processed_at
       FROM withdrawal_requests
       WHERE user_id = ?
       ORDER BY created_at DESC`,
      [req.user.id]
    );

    res.json({
      success: true,
      withdrawals
    });
  } catch (error) {
    console.error('Get withdrawals error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Error fetching withdrawal history'
    });
  }
});


// 7. General Task Routes
app.get('/api/tasks', auth, async (req, res) => {
  try {
    const [tasks] = await pool.query(`
      SELECT t.* 
      FROM tasks t
      WHERE t.participants_count > 0 
        AND t.status = "active" 
        AND t.payment_status = "verified"
        AND t.id NOT IN (
          SELECT task_id 
          FROM user_completed_tasks 
          WHERE user_id = ?
        )
      ORDER BY t.created_at DESC
    `, [req.user.id]);
    
    res.json(tasks);
  } catch (error) {
    console.error('Get tasks error:', error);
    res.status(500).json({ message: 'Server error while fetching tasks' });
  }
});

app.get('/api/tasks/:id', auth, async (req, res) => {
  try {
    const taskId = req.params.id;
    
    const [tasks] = await pool.query(
      'SELECT * FROM tasks WHERE id = ? AND status = "active" AND payment_status = "verified"',
      [taskId]
    );
    
    if (tasks.length === 0) {
      return res.status(404).json({ message: 'Task not found or not available' });
    }
    
    const task = tasks[0];
    res.json(task);
  } catch (error) {
    console.error('Get task error:', error);
    res.status(500).json({ message: 'Server error while fetching task' });
  }
});

app.post('/api/tasks/:id/verify-payment', auth, upload.single('receipt'), async (req, res) => {
  try {
    const taskId = req.params.id;
    const receiptFile = req.file;
    
    const [tasks] = await pool.query(
      'SELECT * FROM tasks WHERE id = ? AND created_by = ?',
      [taskId, req.user.id]
    );
    
    if (tasks.length === 0) {
      if (receiptFile) fs.unlinkSync(receiptFile.path);
      return res.status(404).json({ message: 'Task not found or not authorized' });
    }
    
    const task = tasks[0];
    
    if (!receiptFile) {
      await pool.query(
        `UPDATE tasks 
        SET payment_status = 'verified', 
            status = 'active',
            updated_at = NOW()
        WHERE id = ?`,
        [taskId]
      );
      
      return res.json({ 
        success: true,
        message: 'Task marked for manual verification. Our team will review it shortly.'
      });
    }
    
    console.log('Starting OCR processing...');
    const imageBuffer = fs.readFileSync(receiptFile.path);
    
    const { data: { text } } = await Tesseract.recognize(
      imageBuffer,
      'eng',
      { logger: m => console.log(m) }
    );
    
    console.log('OCR processing completed');
    console.log('Extracted text:', text);
    
    const requiredName = 'ENOCH TIRENIOLUWA BENSON';
    const normalizedText = text.toUpperCase().replace(/\s+/g, ' ');
    const hasName = normalizedText.includes(requiredName.toUpperCase());
    
    if (!hasName) {
      fs.unlinkSync(receiptFile.path);
      return res.status(400).json({ 
        message: 'Verification failed.'
      });
    }
    
    await pool.query(
      `UPDATE tasks 
      SET payment_status = 'verified', 
          status = 'active',
          updated_at = NOW()
      WHERE id = ?`,
      [taskId]
    );
    
    fs.unlinkSync(receiptFile.path);
    
    res.json({ 
      success: true,
      message: 'Payment verified successfully! Task is now active.'
    });
  } catch (error) {
    console.error('Payment verification error:', error);
    if (req.file?.path) fs.unlinkSync(req.file.path);
    res.status(500).json({ message: 'Error processing payment verification' });
  }
});

app.get('/api/submissions/:id', auth, async (req, res) => {
  try {
    const submissionId = req.params.id;
    
    const [submissions] = await pool.query(
      `SELECT pt.*, u.name as user_name, u.email as user_email
       FROM pending_tasks pt
       JOIN users u ON pt.user_id = u.id
       WHERE pt.id = ?`,
      [submissionId]
    );
    
    if (submissions.length === 0) {
      return res.status(404).json({ message: 'Submission not found' });
    }
    
    const submission = submissions[0];
    const [task] = await pool.query(
      'SELECT created_by FROM tasks WHERE id = ?',
      [submission.task_id]
    );
    
    if (task[0].created_by !== req.user.id && submission.user_id !== req.user.id) {
      return res.status(403).json({ message: 'Not authorized to view this submission' });
    }
    
    res.json(submission);
  } catch (error) {
    console.error('Get submission error:', error);
    res.status(500).json({ message: 'Server error while fetching submission' });
  }
});

// 8. Stats and Utility Routes


// Business-specific calculations (WhatsApp status only)
async function calculateBusinessStats(userId, tasks) {
  const [approvedSubmissions] = await pool.query(
    `SELECT COUNT(*) as count 
     FROM pending_tasks 
     WHERE status = 'approved' 
     AND task_id IN (SELECT id FROM tasks WHERE created_by = ? AND platform = 'whatsapp' AND action = 'status')`,
    [userId]
  );

  const activeTasks = tasks.filter(task => task.status === 'active').length;
  const totalCost = tasks.reduce((sum, task) => sum + parseFloat(task.total_cost || 0), 0);
  const totalParticipants = tasks.reduce((sum, task) => sum + (task.participants_count || 0), 0);
  const completedTasks = approvedSubmissions[0]?.count || 0;
  
  return {
    activeTasks,
    totalCost,
    engagementRate: totalParticipants > 0 ? Math.round((completedTasks / totalParticipants) * 100) : 0,
    totalViews: completedTasks * 100, // Estimated views
    completedTasks,
    totalParticipants
  };
}


// Member calculations
async function calculateMemberStats(userId) {
  const [completedTasks] = await pool.query(
    'SELECT COUNT(*) as count FROM user_completed_tasks WHERE user_id = ?',
    [userId]
  );

  const [earnings] = await pool.query(
    `SELECT SUM(amount) as total 
     FROM transactions 
     WHERE user_id = ? 
     AND type = "task_completion" 
     AND status = "completed"`,
    [userId]
  );

  return {
    activeTasks: 0,
    totalEarnings: parseFloat(earnings[0]?.total || 0),
    completedTasks: completedTasks[0]?.count || 0,
    engagementRate: 0
  };
}

app.get('/api/tasks/completed/count', auth, async (req, res) => {
  try {
    const [result] = await pool.query(
      'SELECT COUNT(*) as count FROM user_completed_tasks WHERE user_id = ?',
      [req.user.id]
    );
    
    res.json({ count: result[0].count || 0 });
  } catch (error) {
    console.error('Completed tasks count error:', error);
    res.json({ count: 0 });
  }
});

// 9. Debug Routes
app.get('/api/debug/db-check', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT DATABASE() as db, USER() as user');
    res.json(rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});