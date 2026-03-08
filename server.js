const express = require('express');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const db = require('./db'); // Ensure this exports a mysql2 pool
const crypto = require('crypto');
const https = require('https');
const PDFDocument = require('pdfkit');
require('dotenv').config();

// 1. Initialize the MySQLStore constructor
const MySQLStore = require('express-mysql-session')(session);

// 2. Create the sessionStore instance using your existing db connection
const sessionStore = new MySQLStore({}, db);

const app = express();
const PORT = process.env.PORT || 3000;

// 3. Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));

// 4. Use the sessionStore in your session configuration
app.use(session({
    key: 'mcokoth_session_cookie',
    secret: process.env.SESSION_SECRET || 'mcokoth_secret_key',
    store: sessionStore, // Correctly references the instance created above
    resave: false,
    saveUninitialized: false,
    cookie: { 
        maxAge: 3600000, // 1 hour
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production' // Only use true if on HTTPS
    }
}));
// Nodemailer Transporter Setup
const transporter = nodemailer.createTransport({
    service: process.env.EMAIL_SERVICE,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

// Verify transporter configuration
transporter.verify((error, success) => {
    if (error) {
        console.log('Nodemailer config error:', error);
        console.log('Email functionality may be disabled. Check your .env file and email provider settings.');
    } else {
        console.log('Server is ready to take our messages');
    }
});

// Helper function for professional email styling
const getEmailTemplate = (title, content) => `
<!DOCTYPE html>
<html>
<head>
<style>
    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; }
    .container { max-width: 600px; margin: 20px auto; border: 1px solid #e0e0e0; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 10px rgba(0,0,0,0.05); }
    .header { background-color: #0a192f; color: #ffffff; padding: 30px 20px; text-align: center; }
    .header h1 { margin: 0; font-size: 24px; letter-spacing: 1px; }
    .header span { color: #3b82f6; }
    .content { padding: 30px; background-color: #ffffff; }
    .footer { background-color: #f8f9fa; padding: 20px; text-align: center; font-size: 12px; color: #666; border-top: 1px solid #e0e0e0; }
    .highlight { color: #0077ff; font-weight: bold; }
    ul { list-style-type: none; padding: 0; }
    li { margin-bottom: 12px; border-bottom: 1px solid #eee; padding-bottom: 8px; }
    li:last-child { border-bottom: none; }
    .label { font-weight: bold; color: #555; display: inline-block; width: 120px; }
    .message-box { background: #f0f7ff; padding: 15px; border-radius: 8px; border-left: 4px solid #3b82f6; margin-top: 10px; }
</style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>McOKOTH <span>TECHNOLOGIES</span></h1>
        </div>
        <div class="content">
            <h2 style="color: #0a192f; margin-top: 0;">${title}</h2>
            ${content}
        </div>
        <div class="footer">
            <p><strong>McOKOTH TECHNOLOGIES</strong><br>
            Murang'a Town, near Rubis Fuel Station, Kenya.<br>
            Phone: 0742041208 | Email: oyoookoth42@gmail.com</p>
            <p>&copy; ${new Date().getFullYear()} McOKOTH TECHNOLOGIES. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
`;

// --- AUTHENTICATION ROUTES ---

// Login Endpoint
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    
    try {
        const [rows] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
        
        if (rows.length === 0) {
            return res.status(401).json({ success: false, message: 'Invalid email or password.' });
        }

        const user = rows[0];
        const match = await bcrypt.compare(password, user.password);

        if (match) {
            if (user.status === 'banned') {
                return res.status(403).json({ success: false, message: 'This account has been suspended.' });
            }
            req.session.userId = user.id;
            req.session.role = user.role;
            req.session.user = { name: user.full_name, email: user.email, role: user.role };
            // Set timestamp for "new" notifications for interns
            req.session.lastNotificationCheck = new Date();
            res.json({ success: true, message: 'Login successful', user: req.session.user });
        } else {
            res.status(401).json({ success: false, message: 'Invalid email or password.' });
        }
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ success: false, message: 'Server error during login.' });
    }
});

// Signup Endpoint (For Hosting Users)
app.post('/api/signup', async (req, res) => {
    const { fullName, email, password } = req.body;
    
    try {
        // Check if user exists
        const [exists] = await db.execute('SELECT id FROM users WHERE email = ?', [email]);
        if (exists.length > 0) {
            return res.status(400).json({ success: false, message: 'Email already registered.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        // Default role is 'user' (for hosting clients). Interns are usually added by admin.
        await db.execute('INSERT INTO users (full_name, email, password, role) VALUES (?, ?, ?, ?)', 
            [fullName, email, hashedPassword, 'user']);

        res.json({ success: true, message: 'Account created! Please login.' });
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ success: false, message: 'Error during signup.' });
    }
});

// Logout Endpoint
app.post('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true, message: 'Logged out successfully.' });
});

// Check Session Endpoint
app.get('/api/check-session', (req, res) => {
    if (req.session.user) {
        res.json({ loggedIn: true, user: req.session.user });
    } else {
        res.json({ loggedIn: false });
    }
});

// --- PROTECTED DATA ROUTES ---

const ensureIntern = (req, res, next) => {
    if (req.session.user && (req.session.role === 'intern' || req.session.role === 'admin')) {
        return next();
    }
    res.status(403).json({ success: false, message: 'Forbidden: Intern access only.' });
};

// Get Intern Courses
app.get('/api/courses', ensureIntern, async (req, res) => {
    try {
        const userId = req.session.userId;
        const [rows] = await db.execute(`
            SELECT c.*, COALESCE(ucp.progress, 0) as user_progress 
            FROM courses c 
            LEFT JOIN user_course_progress ucp ON c.id = ucp.course_id AND ucp.user_id = ? 
            ORDER BY c.created_at DESC
        `, [userId]);

        const courses = rows.map(c => ({
            id: c.id,
            title: c.title,
            desc: c.description,
            videoUrl: c.video_url,
            progress: c.user_progress
        }));
        res.json({ success: true, courses });
    } catch (error) {
        console.error('Fetch courses error:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch courses.' });
    }
});

// Generate Certificate
app.get('/api/certificate/:courseId', ensureIntern, async (req, res) => {
    const courseId = req.params.courseId;
    const userId = req.session.userId;

    try {
        // Verify 100% progress
        const [rows] = await db.execute('SELECT progress FROM user_course_progress WHERE user_id = ? AND course_id = ?', [userId, courseId]);
        
        if (rows.length === 0 || rows[0].progress < 100) {
            return res.status(403).send('Certificate not available. Please complete the course first.');
        }

        const [course] = await db.execute('SELECT title FROM courses WHERE id = ?', [courseId]);
        const courseTitle = course[0].title;
        const userName = req.session.user.name;
        const date = new Date().toLocaleDateString();
        
        const doc = new PDFDocument({ layout: 'landscape', size: 'A4', margin: 50 });
        
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename=Certificate-${courseTitle.replace(/\s+/g, '_')}.pdf`);
        
        doc.pipe(res);
        
        // Decorative Border
        doc.lineWidth(10).strokeColor('#0a192f').rect(20, 20, doc.page.width - 40, doc.page.height - 40).stroke();
        doc.lineWidth(2).strokeColor('#0a192f').rect(35, 35, doc.page.width - 70, doc.page.height - 70).stroke();
        
        // Content
        doc.moveDown(2);
        doc.font('Helvetica-Bold').fontSize(40).fillColor('#0a192f').text('Certificate of Completion', { align: 'center' });
        doc.moveDown(1);
        doc.font('Helvetica-Oblique').fontSize(20).fillColor('black').text('This is to certify that', { align: 'center' });
        doc.moveDown(1);
        doc.font('Helvetica-Bold').fontSize(30).text(userName, { align: 'center' });
        doc.moveDown(0.5);
        doc.font('Helvetica').fontSize(18).text('has successfully completed the course', { align: 'center' });
        doc.moveDown(1);
        doc.font('Helvetica-Bold').fontSize(28).fillColor('#0077ff').text(courseTitle, { align: 'center' });
        doc.moveDown(1);
        doc.font('Helvetica').fontSize(16).fillColor('black').text(`Dated: ${date}`, { align: 'center' });
        
        doc.end();
    } catch (error) {
        console.error('Certificate error:', error);
        res.status(500).send('Error generating certificate.');
    }
});

// Update Course Progress
app.post('/api/courses/:id/progress', ensureIntern, async (req, res) => {
    const courseId = req.params.id;
    const { progress } = req.body;
    const userId = req.session.userId;

    try {
        await db.execute(`
            INSERT INTO user_course_progress (user_id, course_id, progress) 
            VALUES (?, ?, ?) 
            ON DUPLICATE KEY UPDATE progress = ?
        `, [userId, courseId, progress, progress]);
        res.json({ success: true, message: 'Progress updated' });
    } catch (error) {
        console.error('Update progress error:', error);
        res.status(500).json({ success: false, message: 'Failed to update progress' });
    }
});

// Get comments for a course
app.get('/api/courses/:id/comments', ensureIntern, async (req, res) => {
    const { id } = req.params;
    try {
        const [comments] = await db.execute(`
            SELECT cc.comment, cc.created_at, u.full_name 
            FROM course_comments cc
            JOIN users u ON cc.user_id = u.id
            WHERE cc.course_id = ?
            ORDER BY cc.created_at ASC
        `, [id]);
        res.json({ success: true, comments });
    } catch (error) {
        console.error('Fetch comments error:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch comments.' });
    }
});

// Post a comment on a course
app.post('/api/courses/:id/comments', ensureIntern, async (req, res) => {
    const { id } = req.params;
    const { comment } = req.body;
    const userId = req.session.userId;

    if (!comment || comment.trim() === '') {
        return res.status(400).json({ success: false, message: 'Comment cannot be empty.' });
    }

    try {
        await db.execute('INSERT INTO course_comments (course_id, user_id, comment) VALUES (?, ?, ?)', [id, userId, comment]);
        res.json({ success: true, message: 'Comment posted.' });
    } catch (error) {
        console.error('Post comment error:', error);
        res.status(500).json({ success: false, message: 'Failed to post comment.' });
    }
});

// Get Intern Exams
app.get('/api/exams', ensureIntern, async (req, res) => {
    try {
        const userId = req.session.userId;
        const [rows] = await db.execute(`
            SELECT e.*, uec.completed_at 
            FROM exams e 
            LEFT JOIN user_exam_completions uec ON e.id = uec.exam_id AND uec.user_id = ? 
            ORDER BY e.created_at DESC
        `, [userId]);
        
        const exams = rows.map(e => ({
            ...e,
            isCompleted: !!e.completed_at
        }));
        res.json({ success: true, exams });
    } catch (error) {
        console.error('Fetch exams error:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch exams.' });
    }
});

// Mark Exam as Completed
app.post('/api/exams/:id/complete', ensureIntern, async (req, res) => {
    const examId = req.params.id;
    const userId = req.session.userId;
    try {
        await db.execute('INSERT IGNORE INTO user_exam_completions (user_id, exam_id) VALUES (?, ?)', [userId, examId]);
        res.json({ success: true, message: 'Exam marked as completed.' });
    } catch (error) {
        console.error('Exam completion error:', error);
        res.status(500).json({ success: false, message: 'Error marking exam as completed.' });
    }
});

// --- PAYSTACK PAYMENT ROUTES ---

app.post('/api/paystack/initialize', async (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ success: false, message: 'Please login to subscribe.' });
    }

    const { plan, amount } = req.body;
    const email = req.session.user.email;
    
    // Convert amount to kobo (Paystack expects amount in lowest currency unit)
    const amountInKobo = amount * 100; 
    
    const params = JSON.stringify({
        email: email,
        amount: amountInKobo,
        metadata: {
            plan: plan,
            user_id: req.session.userId
        },
        callback_url: `${req.protocol}://${req.get('host')}/api/paystack/callback`
    });

    const options = {
        hostname: 'api.paystack.co',
        port: 443,
        path: '/transaction/initialize',
        method: 'POST',
        headers: {
            Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
            'Content-Type': 'application/json'
        }
    };

    const request = https.request(options, response => {
        let data = '';
        response.on('data', (chunk) => { data += chunk; });
        response.on('end', () => {
            const result = JSON.parse(data);
            if (result.status) {
                res.json({ success: true, authorization_url: result.data.authorization_url });
            } else {
                res.status(400).json({ success: false, message: result.message });
            }
        });
    });

    request.on('error', error => {
        console.error(error);
        res.status(500).json({ success: false, message: 'Payment initialization failed' });
    });

    request.write(params);
    request.end();
});

app.get('/api/paystack/callback', async (req, res) => {
    const reference = req.query.reference;
    
    const options = {
        hostname: 'api.paystack.co',
        port: 443,
        path: `/transaction/verify/${reference}`,
        method: 'GET',
        headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` }
    };

    const request = https.request(options, response => {
        let data = '';
        response.on('data', (chunk) => { data += chunk; });
        response.on('end', async () => {
            const result = JSON.parse(data);
            if (result.status && result.data.status === 'success') {
                const { plan, user_id } = result.data.metadata;
                const amount = result.data.amount / 100;

                try {
                    // Deactivate old subscriptions
                    await db.execute('UPDATE hosting_subscriptions SET status = "expired" WHERE user_id = ?', [user_id]);
                    // Activate new subscription
                    await db.execute('INSERT INTO hosting_subscriptions (user_id, plan_name, amount, status) VALUES (?, ?, ?, "active")', [user_id, plan, amount]);
                    
                    res.redirect('/hosting?payment=success&plan=' + plan);
                } catch (dbError) {
                    console.error(dbError);
                    res.redirect('/hosting?payment=error');
                }
            } else {
                res.redirect('/hosting?payment=failed');
            }
        });
    });
    request.on('error', error => res.redirect('/hosting?payment=error'));
    request.end();
});

// Get Transaction History
app.get('/api/transactions', async (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ success: false, message: 'Unauthorized' });
    }
    try {
        const [rows] = await db.execute('SELECT * FROM hosting_subscriptions WHERE user_id = ? ORDER BY created_at DESC', [req.session.userId]);
        res.json({ success: true, transactions: rows });
    } catch (error) {
        console.error('Transaction history error:', error);
        res.status(500).json({ success: false, message: 'Error fetching transactions' });
    }
});

// Get Hosting Services
app.get('/api/hosting-services', (req, res) => {
    if (!req.session.user || (req.session.role !== 'user' && req.session.role !== 'admin')) {
        return res.status(401).json({ success: false, message: 'Unauthorized. Client access only.' });
    }
    res.json({ success: true, services: [
        { name: 'Server Console', status: 'Active', ip: '192.168.1.105' },
        { name: 'Deployment Pipeline', status: 'Idle', lastRun: '2 hours ago' },
        { name: 'Domain Management', domains: ['mcokoth.tech', 'client-site.com'] }
    ]});
});

// --- ADMIN ROUTES ---

const ensureAdmin = (req, res, next) => {
    if (req.session.user && req.session.role === 'admin') {
        return next();
    }
    res.status(403).json({ success: false, message: 'Forbidden: Admin access only.' });
};

app.get('/api/admin/dashboard', ensureAdmin, async (req, res) => {
    try {
        const [applications] = await db.execute('SELECT * FROM internship_applications ORDER BY created_at DESC');
        const [contacts] = await db.execute('SELECT * FROM contact_submissions ORDER BY created_at DESC');
        const [support] = await db.execute('SELECT * FROM support_requests ORDER BY created_at DESC');
        
        // Stats Calculations
        const [userCounts] = await db.execute("SELECT role, COUNT(*) as count FROM users GROUP BY role");
        const [statusCounts] = await db.execute("SELECT status, COUNT(*) as count FROM users GROUP BY status");
        const [revenueData] = await db.execute("SELECT SUM(amount) as total FROM hosting_subscriptions");
        const [hostingPlans] = await db.execute("SELECT plan_name, COUNT(*) as count FROM hosting_subscriptions GROUP BY plan_name");

        let stats = {
            totalUsers: 0,
            interns: 0,
            hostingClients: 0,
            activeUsers: 0,
            revenue: revenueData[0]?.total || 0,
            hostingBreakdown: hostingPlans
        };

        userCounts.forEach(row => {
            stats.totalUsers += row.count;
            if (row.role === 'intern') stats.interns = row.count;
            if (row.role === 'user') stats.hostingClients = row.count;
        });

        statusCounts.forEach(row => {
            if (row.status === 'active') stats.activeUsers = row.count;
        });

        res.json({ success: true, applications, contacts, support, stats });
    } catch (error) {
        console.error('Admin dashboard error:', error);
        res.status(500).json({ success: false, message: 'Server error fetching admin data.' });
    }
});

// Get Notifications
app.get('/api/admin/notifications', ensureAdmin, async (req, res) => {
    try {
        const [notifications] = await db.execute('SELECT * FROM notifications ORDER BY created_at DESC LIMIT 10');
        const [unread] = await db.execute('SELECT COUNT(*) as count FROM notifications WHERE is_read = 0');
        res.json({ success: true, notifications, unreadCount: unread[0].count });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error fetching notifications' });
    }
});

// Mark Notifications as Read
app.post('/api/admin/notifications/mark-read', ensureAdmin, async (req, res) => {
    try {
        await db.execute('UPDATE notifications SET is_read = 1 WHERE is_read = 0');
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error updating notifications' });
    }
});

// Get All Users
app.get('/api/admin/users', ensureAdmin, async (req, res) => {
    try {
        const [users] = await db.execute('SELECT id, full_name, email, role, status, created_at FROM users ORDER BY created_at DESC');
        res.json({ success: true, users });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error fetching users' });
    }
});

// Ban/Unban User
app.post('/api/admin/users/:id/status', ensureAdmin, async (req, res) => {
    const { status } = req.body; // 'active' or 'banned'
    const { id } = req.params;
    try {
        await db.execute('UPDATE users SET status = ? WHERE id = ?', [status, id]);
        res.json({ success: true, message: `User ${status} successfully.` });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error updating user status' });
    }
});

// Add Course
app.post('/api/admin/courses', ensureAdmin, async (req, res) => {
    const { title, description, videoUrl } = req.body;
    try {
        await db.execute('INSERT INTO courses (title, description, video_url) VALUES (?, ?, ?)', [title, description, videoUrl]);
        await db.execute('INSERT INTO notifications (message, type, recipient_role) VALUES (?, ?, ?)', [`New course added: ${title}`, 'course', 'intern']);
        res.json({ success: true, message: 'Course added successfully.' });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error adding course' });
    }
});

// Delete Course
app.delete('/api/admin/courses/:id', ensureAdmin, async (req, res) => {
    try {
        await db.execute('DELETE FROM courses WHERE id = ?', [req.params.id]);
        res.json({ success: true, message: 'Course deleted successfully.' });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error deleting course' });
    }
});

// Add Exam
app.post('/api/admin/exams', ensureAdmin, async (req, res) => {
    const { title, link, duration } = req.body;
    try {
        await db.execute('INSERT INTO exams (title, link, duration) VALUES (?, ?, ?)', [title, link, duration || 0]);
        await db.execute('INSERT INTO notifications (message, type, recipient_role) VALUES (?, ?, ?)', [`New exam posted: ${title}`, 'exam', 'intern']);
        res.json({ success: true, message: 'Exam added successfully.' });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error adding exam' });
    }
});

// Delete Exam
app.delete('/api/admin/exams/:id', ensureAdmin, async (req, res) => {
    try {
        await db.execute('DELETE FROM exams WHERE id = ?', [req.params.id]);
        res.json({ success: true, message: 'Exam deleted successfully.' });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error deleting exam' });
    }
});

// Get Intern Notifications
app.get('/api/intern/notifications', ensureIntern, async (req, res) => {
    try {
        const [notifications] = await db.execute("SELECT * FROM notifications WHERE recipient_role = 'intern' ORDER BY created_at DESC LIMIT 10");
        const [unread] = await db.execute("SELECT COUNT(*) as count FROM notifications WHERE recipient_role = 'intern' AND created_at > ?", [req.session.lastNotificationCheck || new Date(0)]);
        res.json({ success: true, notifications, unreadCount: unread[0].count });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error fetching notifications' });
    }
});

// Mark Intern Notifications as "Read"
app.post('/api/intern/notifications/mark-read', ensureIntern, (req, res) => {
    // We update the session timestamp to mark all current notifications as "seen".
    req.session.lastNotificationCheck = new Date();
    res.json({ success: true });
});

app.post('/api/admin/approve-intern', ensureAdmin, async (req, res) => {
    const { applicationId, name, email } = req.body;
    const tempPassword = crypto.randomBytes(8).toString('hex');

    try {
        const hashedPassword = await bcrypt.hash(tempPassword, 10);
        await db.execute('INSERT INTO users (full_name, email, password, role) VALUES (?, ?, ?, ?)', [name, email, hashedPassword, 'intern']);
        await db.execute('UPDATE internship_applications SET status = "approved" WHERE id = ?', [applicationId]);

        // Email credentials to the new intern
        const mailOptions = {
            from: `"McOKOTH TECHNOLOGIES" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Your Internship Application is Approved!',
            html: getEmailTemplate('Welcome to the Team!', `<p>Hi ${name},</p><p>Congratulations! Your internship application has been approved. You can now log in to our intern portal using the following credentials:</p><ul><li><span class="label">Email:</span> ${email}</li><li><span class="label">Password:</span> <strong>${tempPassword}</strong></li></ul><p>We recommend changing your password upon first login. Welcome aboard!</p>`)
        };
        await transporter.sendMail(mailOptions);

        res.json({ success: true, message: 'Intern approved and credentials sent.' });
    } catch (error) {
        console.error('Approve intern error:', error);
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(400).json({ success: false, message: 'This user already exists.' });
        }
        res.status(500).json({ success: false, message: 'Server error during approval.' });
    }
});

// API endpoint for Bot Handoff
app.post('/api/request-support', async (req, res) => {
    const { email, message } = req.body;
    try {
        await db.execute('INSERT INTO support_requests (requester_email, initial_message) VALUES (?, ?)', [email, message]);
        await db.execute('INSERT INTO notifications (message, type) VALUES (?, ?)', [`New support request from ${email}`, 'support']);
        res.json({ success: true, message: 'Support request sent. A human will contact you via email shortly.' });
    } catch (error) {
        console.error('Support request error:', error);
        res.status(500).json({ success: false, message: 'Failed to send support request.' });
    }
});

// API endpoint for Internship form
app.post('/api/internship', async (req, res) => {
    const { name, email, phone, expertise } = req.body;

    if (!name || !email || !phone || !expertise) {
        return res.status(400).json({ success: false, message: 'Please fill out all fields.' });
    }

    try {
        // Save to database
        await db.execute('INSERT INTO internship_applications (name, email, phone, expertise) VALUES (?, ?, ?, ?)', [name, email, phone, expertise]);
        await db.execute('INSERT INTO notifications (message, type) VALUES (?, ?)', [`New internship application: ${name}`, 'application']);

    } catch (dbError) {
        console.error('Internship DB save error:', dbError);
        return res.status(500).json({ success: false, message: 'Failed to save application to database.' });
    }

    const mailToCompanyOptions = {
        from: `"Internship Bot" <${process.env.EMAIL_USER}>`,
        replyTo: email,
        to: process.env.EMAIL_USER,
        subject: 'New Internship Application via Website',
        html: getEmailTemplate('New Internship Application', `
            <p><strong>Applicant Details:</strong></p>
            <ul>
                <li><span class="label">Name:</span> ${name}</li>
                <li><span class="label">Email:</span> <a href="mailto:${email}">${email}</a></li>
                <li><span class="label">Phone:</span> ${phone}</li>
                <li><span class="label">Expertise:</span> ${expertise}</li>
            </ul>
        `),
    };

    const mailToApplicantOptions = {
        from: `"McOKOTH TECHNOLOGIES" <${process.env.EMAIL_USER}>`,
        to: email,
        subject: 'Your Internship Application has been Received',
        html: getEmailTemplate('Application Received', `
            <p>Hi ${name},</p>
            <p>Thank you for your interest in <span class="highlight">McOKOTH TECHNOLOGIES</span>. We have successfully received your internship application.</p>
            <p><strong>Your Submission:</strong></p>
            <ul>
                <li><span class="label">Name:</span> ${name}</li>
                <li><span class="label">Email:</span> ${email}</li>
                <li><span class="label">Phone:</span> ${phone}</li>
                <li><span class="label">Expertise:</span> ${expertise}</li>
            </ul>
            <p>Our team will review your application and get back to you as soon as possible.</p>
        `),
    };

    try {
        await transporter.sendMail(mailToCompanyOptions);
        await transporter.sendMail(mailToApplicantOptions);
        res.json({ success: true, message: 'Application submitted! A confirmation email has been sent to you.' });
    } catch (error) {
        console.error('Internship form email error:', error);
        res.status(500).json({ success: false, message: 'Failed to send application. Please try again later.' });
    }
});

// API endpoint for Contact form
app.post('/api/contact', async (req, res) => {
    const { name, email, service, message } = req.body;

    if (!name || !email || !service || !message) {
        return res.status(400).json({ success: false, message: 'Please fill out all fields.' });
    }

    try {
        // Save to database
        await db.execute('INSERT INTO contact_submissions (name, email, service, message) VALUES (?, ?, ?, ?)', [name, email, service, message]);
        await db.execute('INSERT INTO notifications (message, type) VALUES (?, ?)', [`New contact message from ${name}`, 'contact']);
    } catch (dbError) {
        console.error('Contact DB save error:', dbError);
        return res.status(500).json({ success: false, message: 'Failed to save contact submission to database.' });
    }

    const mailToCompanyOptions = {
        from: `"Service Request Bot" <${process.env.EMAIL_USER}>`,
        replyTo: email,
        to: process.env.EMAIL_USER,
        subject: `New Contact Request: ${service}`,
        html: getEmailTemplate(`New Request: ${service}`, `
            <p><strong>Client Details:</strong></p>
            <ul>
                <li><span class="label">Name:</span> ${name}</li>
                <li><span class="label">Email:</span> <a href="mailto:${email}">${email}</a></li>
                <li><span class="label">Service:</span> ${service}</li>
            </ul>
            <p><strong>Message:</strong></p>
            <div class="message-box">${message}</div>
        `),
    };

    const mailToUserOptions = {
        from: `"McOKOTH TECHNOLOGIES" <${process.env.EMAIL_USER}>`,
        to: email,
        subject: 'We received your service request',
        html: getEmailTemplate('Request Received', `
            <p>Hi ${name},</p>
            <p>Thank you for contacting <span class="highlight">McOKOTH TECHNOLOGIES</span>.</p>
            <p>We have received your inquiry regarding <strong>${service}</strong>.</p>
            <p><strong>Your Message:</strong></p>
            <div class="message-box">${message}</div>
            <p>One of our tech experts will review your request and contact you within 24 hours.</p>
        `),
    };

    try {
        await transporter.sendMail(mailToCompanyOptions);
        await transporter.sendMail(mailToUserOptions);
        res.json({ success: true, message: 'Your message has been sent! Check your email for confirmation.' });
    } catch (error) {
        console.error('Contact form email error:', error);
        res.status(500).json({ success: false, message: 'Failed to send message. Please try again later.' });
    }
});

// --- PASSWORD RESET ROUTES ---

// Forgot Password - Request Token
app.post('/api/forgot-password', async (req, res) => {
    const { email } = req.body;
    try {
        const [rows] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
        if (rows.length === 0) {
            return res.json({ success: true, message: 'If an account exists, a reset link has been sent.' });
        }

        const user = rows[0];
        const token = crypto.randomBytes(32).toString('hex');
        const expireTime = new Date(Date.now() + 3600000); // 1 hour from now

        await db.execute('UPDATE users SET reset_token = ?, reset_token_expires = ? WHERE id = ?', [token, expireTime, user.id]);

        const resetLink = `${req.protocol}://${req.get('host')}/reset-password?token=${token}`;

        const mailOptions = {
            from: `"Security Team" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Password Reset Request',
            html: getEmailTemplate('Reset Your Password', `
                <p>We received a request to reset your password.</p>
                <p>Click the button below to set a new password. This link expires in 1 hour.</p>
                <div style="text-align: center; margin: 30px 0;">
                    <a href="${resetLink}" style="background-color: #0077ff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: bold;">Reset Password</a>
                </div>
                <p>If you didn't request this, you can safely ignore this email.</p>
            `)
        };

        await transporter.sendMail(mailOptions);
        res.json({ success: true, message: 'Reset link sent to your email.' });
    } catch (error) {
        console.error('Forgot password error:', error);
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// Reset Password - Set New Password
app.post('/api/reset-password', async (req, res) => {
    const { token, newPassword } = req.body;
    try {
        const [rows] = await db.execute('SELECT * FROM users WHERE reset_token = ? AND reset_token_expires > NOW()', [token]);
        
        if (rows.length === 0) {
            return res.status(400).json({ success: false, message: 'Invalid or expired token.' });
        }

        const user = rows[0];
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        await db.execute('UPDATE users SET password = ?, reset_token = NULL, reset_token_expires = NULL WHERE id = ?', [hashedPassword, user.id]);

        res.json({ success: true, message: 'Password reset successful. You can now login.' });
    } catch (error) {
        console.error('Reset password error:', error);
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});
app.get('/ping', (req, res) => {
    res.json({
        status: "OK",
        uptime: process.uptime(),
        timestamp: Date.now()
    });
});
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});