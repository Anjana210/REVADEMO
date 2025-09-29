const express = require('express');
const app = express();
const path = require('node:path');
const http = require('http');
const { Server } = require("socket.io");
const axios = require('axios');
const cors = require('cors');
const session = require('express-session');

const port = process.env.PORT || 4000;

app.set('view engine', 'ejs');
app.use(cors({ origin: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: 'a-secure-secret-key-for-revartix',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false }
}));

// Middleware to protect routes
const requireLogin = (req, res, next) => {
  if (!req.session.user) {
    return res.redirect('/');
  }
  next();
};

// --- ROUTES ---

// Root route now redirects logged-in users to home
app.get('/', (req, res) => {
  if (req.session.user) {
    return res.redirect('/home');
  }
  res.render('login', { error: null }); // Pass null error on first load
});


// Login route
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const odooUrl = 'http://insiderevartix-contacts-22767503.dev.odoo.com/web/session/authenticate';
  const payload = {
    jsonrpc: "2.0",
    method: "call",
    params: {
      db: "insiderevartix-contacts-22767503",
      login: username,
      password: password,
    }
  };

  try {
    const response = await axios.post(odooUrl, payload, {
      headers: { 'Content-Type': 'application/json' }
    });

    if (response.data.result) {
      req.session.user = {
        name: response.data.result.name,
        uid: response.data.result.uid
      };
      res.redirect('/home');
    } else {
      // **IMPROVED:** Render login with an error message
      res.render('login', { error: 'Invalid username or password. Please try again.' });
    }
  } catch (error) {
    console.error("Error connecting to Odoo:", error.message);
    res.render('login', { error: 'Could not connect to the authentication server.' });
  }
});

// Logout Route
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.redirect('/home');
    }
    res.clearCookie('connect.sid');
    res.redirect('/');
  });
});


// Home Page Route
app.get('/home', requireLogin, async (req, res) => {
  const odooUrl = 'http://insiderevartix-contacts-22767503.dev.odoo.com/jsonrpc';
  const payload = { /* ... your odoo payload ... */ };

  try {
    // For demonstration, using placeholder data instead of making a live call
    const records = [
        { x_name: 'Recent Activity 1', x_studio_data_value: 100, x_studio_timestamp: '2025-09-28' },
        { x_name: 'Recent Activity 2', x_studio_data_value: 250, x_studio_timestamp: '2025-09-27' }
    ];

    res.render('home', {
      records: records, // Using placeholder records
      user: req.session.user,
      activePage: 'home'
    });

  } catch (error) {
    console.error("Error fetching data from Odoo:", error.message);
    res.send('<h1>Error</h1><p>Could not fetch data from the database.</p>');
  }
});

// Dashboard Page Route
app.get('/dashboard', requireLogin, (req, res) => {
  res.render('dashboard', {
    user: req.session.user,
    grafanaPublicBase: 'http://localhost:3000/public-dashboards',
    dashboardId: '06e4035d72ae479fb65d30ba7edb72d6',
    initialTheme: 'dark',
    activePage: 'dashboard'
  });
});

// --- NEW: Placeholder Routes for other pages ---
app.get('/billing', requireLogin, (req, res) => {
    res.render('billing', { user: req.session.user, activePage: 'billing' });
});

app.get('/usage-details', requireLogin, (req, res) => {
    // Data updated with the Saudi Riyal (SAR) symbol
    const usageData = [
        { areaName: 'Al Malaz', consumption: '12,500', amount: 'SAR 350.00', status: 'Pending' },
        { areaName: 'Olaya', consumption: '18,200', amount: 'SAR 510.50', status: 'Overdue' },
        { areaName: 'Al Diriyah', consumption: '14,800', amount: 'SAR 415.20', status: 'Paid' },
        { areaName: 'Al Rawdah', consumption: '11,300', amount: 'SAR 315.00', status: 'Paid' },
        { areaName: 'King Abdullah Financial District', consumption: '25,500', amount: 'SAR 780.00', status: 'Overdue' },
        { areaName: 'Al Shifa', consumption: '13,900', amount: 'SAR 390.75', status: 'Paid' },
        { areaName: 'Irqah', consumption: '10,500', amount: 'SAR 290.00', status: 'Paid' },
        { areaName: 'Al-Naseem', consumption: '16,000', amount: 'SAR 450.00', status: 'Pending' },
    ];

    res.render('usage-details', { 
        user: req.session.user, 
        activePage: 'usage-details',
        data: usageData 
    });
});

app.get('/reports', requireLogin, (req, res) => {
    // In a real app, you would fetch this report history from your database
    const reportsData = [
        { reportType: 'Monthly Consumption', dateRange: '01/01/2024 - 01/31/2024', format: 'PDF', generatedOn: '02/01/2024' },
        { reportType: 'Billing History', dateRange: '01/01/2023 - 12/31/2023', format: 'CSV', generatedOn: '01/15/2024' },
        { reportType: 'Comparative Analysis', dateRange: 'Q1 2023 vs Q1 2024', format: 'PDF', generatedOn: '04/01/2024' }
    ];

    res.render('reports', { 
        user: req.session.user, 
        activePage: 'reports',
        data: reportsData 
    });
});

app.get('/settings', requireLogin, (req, res) => {
    // In a real app, you would fetch this from your database
    const paymentMethods = [
        { id: 1, type: 'Visa', details: 'ending in 1234', expiry: '08/2026', isDefault: true },
        { id: 2, type: 'Bank Account', details: 'ending in 5678', accountType: 'Checking Account', isDefault: false }
    ];

    res.render('settings', { 
        user: req.session.user, 
        activePage: 'settings',
        paymentMethods: paymentMethods
    });
});


const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

io.on('connection', (socket) => {
  console.log('A user connected with ID:', socket.id);
  socket.on('disconnect', () => {
    console.log('User disconnected');
  });
});

server.listen(port, () => {
  console.log(`✅ Server is running on http://localhost:${port}`);
});
