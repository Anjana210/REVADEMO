const express = require('express');
const app = express();
const path = require('node:path');
const http = require('http');
const { Server } = require("socket.io");
// const axios = require('axios'); // Removed
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

// --- NEW: Middleware for Role-Based Access Control ---

// Middleware to ensure user is a logged-in Admin
const requireAdmin = (req, res, next) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        // If not an admin, deny access. You can redirect or show an error.
        return res.status(403).send('<h1>403 Forbidden</h1><p>You do not have permission to access this page.</p>');
    }
    next();
};

// Middleware to ensure user is a logged-in Customer
const requireCustomer = (req, res, next) => {
    if (!req.session.user || req.session.user.role !== 'customer') {
        // If not a customer, deny access.
        return res.status(403).send('<h1>403 Forbidden</h1><p>You do not have permission to access this page.</p>');
    }
    next();
};


// --- UPDATED ROUTES ---

// UPDATED: Root route now redirects based on the user's role if a session exists
app.get('/', (req, res) => {
  if (req.session.user) {
    if (req.session.user.role === 'admin') {
      return res.redirect('/admin/home');
    }
    // Default to customer home for any other role
    return res.redirect('/home');
  }
  // If no session, show the login page
  res.render('Customer/login', { error: null });
});


// UPDATED: Login route now assigns roles and redirects
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // --- Check for Admin credentials ---
  if (username === 'admin_demo' && password === 'Demo@123') {
    req.session.user = {
      name: 'Admin User Demo',
      uid: 'demo_admin_01',
      role: 'admin' // Assign 'admin' role
    };
    // Redirect to the dedicated admin home route
    return res.redirect('/admin/home');
  }

  // --- Check for Customer credentials ---
  if (username === 'customer_demo' && password === 'Demo@123') {
    req.session.user = {
      name: 'Customer User Demo',
      uid: 1,
      role: 'customer' // Assign 'customer' role
    };
    return res.redirect('/home');
  }

  // --- Fallback for failed login ---
  res.render('Customer/login', { error: 'Invalid username or password. Please try again.' });
});

// Logout Route - works for both roles
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.redirect('/');
    }
    res.clearCookie('connect.sid');
    res.redirect('/');
  });
});


//---------------------------------------------------------------------------------------//


// --- NEW: Admin Routes ---
// All routes for the admin panel should be placed here and use `requireAdmin`

app.get('/admin/home', requireAdmin, (req, res) => {
    // This page is now protected and only accessible by admins
    res.render('Admin/home_ad', {
        user: req.session.user,
        activePage: 'home'
    });
});


app.get('/admin/customer_management', requireAdmin, (req, res) => {
    // This page is now protected and only accessible by admins
    res.render('Admin/customer_management', {
        user: req.session.user,
        activePage: 'customer_management'
    });
});

app.get('/admin/meter_management', requireAdmin, (req, res) => {
    // This page is now protected and only accessible by admins
    res.render('Admin/meter_management', {
        user: req.session.user,
        activePage: 'meter_management'
    });
});

app.get('/admin/billing_finance', requireAdmin, (req, res) => {
    // This page is now protected and only accessible by admins
    res.render('Admin/billing_finance', {
        user: req.session.user,
        activePage: 'billing_finance'
    });
});

app.get('/admin/analytics_reports', requireAdmin, (req, res) => {
    // This page is now protected and only accessible by admins
    res.render('Admin/analytics_reports', {
        user: req.session.user,
        activePage: 'analytics_reports'
    });
});

app.get('/admin/dashboards', requireAdmin, (req, res) => {
    // This page is now protected and only accessible by admins
    res.render('Admin/dashboards', {
        user: req.session.user,
        activePage: 'dashboards'
    });
});

app.get('/admin/settings', requireAdmin, (req, res) => {
    // This page is now protected and only accessible by admins
    res.render('Admin/settings', {
        user: req.session.user,
        activePage: 'settings'
    });
});

app.get('/admin/support_center', requireAdmin, (req, res) => {
    // This page is now protected and only accessible by admins
    res.render('Admin/support_center', {
        user: req.session.user,
        activePage: 'support_center'
    });
});

//---------------------------------------------------------------------------------------//

   



// --- PROTECTED Customer Routes ---
// All customer routes now use `requireCustomer` for protection

// Home Page Route - Odoo references removed
app.get('/home', requireCustomer, (req, res) => {
    // Using placeholder data for demonstration

    res.render('Customer/home', {
      records: masterMeterData,
      user: req.session.user,
      activePage: 'home'
    });
});

// Dashboard Page Route
app.get('/dashboards', requireCustomer, (req, res) => {
    const parseNumber = (str) => {
        if (typeof str !== 'string') return 0;
        return parseFloat(str.replace(/[^0-9.-]+/g, "")) || 0;
    };
    const totalMeters = masterMeterData.length;
    const activeMeters = masterMeterData.filter(m => m.status === 'Active').length;
    const totalConsumption = masterMeterData.reduce((sum, meter) => sum + parseNumber(meter.totalReadings), 0);
    const totalBilled = masterMeterData.reduce((sum, meter) => {
        const debitPayments = meter.paymentHistory.filter(p => p.type === 'Debit');
        return sum + debitPayments.reduce((subSum, p) => subSum + parseNumber(p.amount), 0);
    }, 0);

    // In a real app, you would process your chart data here 

    res.render('Customer/dashboards', {
        user: req.session.user,
        activePage: 'dashboards',
        kpis: { totalMeters, activeMeters, totalConsumption, totalBilled: Math.abs(totalBilled) },
        charts: { /* chart data would go here */ },
        attentionMeters: masterMeterData.filter(m => m.status === 'Needs Attention'),
        recentPayments: masterMeterData
            .flatMap(meter => meter.paymentHistory.map(p => ({ ...p, meterId: meter.id })))
            .sort((a, b) => new Date(b.date) - new Date(a.date))
            .slice(0, 5),
        mapData: masterMeterData
    });
});

// Billing Page Route
app.get('/billing', requireCustomer, (req, res) => {
    res.render('Customer/billing', { user: req.session.user, activePage: 'billing' });
});

// Reports Page Route
app.get('/reports', requireCustomer, (req, res) => {
    const reportsData = [
        { reportType: 'Monthly Consumption', dateRange: '01/01/2024 - 01/31/2024', format: 'PDF', generatedOn: '02/01/2024' },
        { reportType: 'Billing History', dateRange: '01/01/2023 - 12/31/2023', format: 'CSV', generatedOn: '01/15/2024' },
        { reportType: 'Comparative Analysis', dateRange: 'Q1 2023 vs Q1 2024', format: 'PDF', generatedOn: '04/01/2024' }
    ];
    res.render('Customer/reports', { user: req.session.user, activePage: 'reports', data: reportsData });
});

// Settings Page Route
app.get('/settings', requireCustomer, (req, res) => {
    const paymentMethods = [
        { id: 1, type: 'Visa', details: 'ending in 1234', expiry: '08/2026', isDefault: true },
        { id: 2, type: 'Bank Account', details: 'ending in 5678', accountType: 'Checking Account', isDefault: false }
    ];
    res.render('Customer/settings', { user: req.session.user, activePage: 'settings', paymentMethods: paymentMethods });
});

// Meters Page Route
app.get('/meters', requireCustomer, (req, res) => {
    const { status } = req.query;
    let filteredMeters = masterMeterData;
    if (status) {
        filteredMeters = masterMeterData.filter(meter => meter.status === status);
    }
    res.render('Customer/meters', {
        user: req.session.user,
        activePage: 'meters',
        meters: filteredMeters,
        activeFilter: status || 'All Meters'
    });
});

// Usage Details Page Route
app.get('/usage-details', requireCustomer, (req, res) => {
    const usageData = masterMeterData.map(m => ({...m, locationName: m.location, id: `#${m.id}`}));
    res.render('Customer/usage-details', {
        user: req.session.user,
        activePage: 'usage-details',
        data: usageData
    });
});

// My Account Page Route
app.get('/my_account', requireCustomer, (req, res) => {
    // Placeholder data for the account page
    const accountInfo = {
        serviceAddress: '1234 Olaya St, Al-Sulimaniah, Riyadh 12245, Saudi Arabia',
        email: 'customer.demo@example.com',
        phone: '+966 55 123 4567',
        paymentMethod: {
            type: 'Visa',
            lastFour: '1234',
            expiry: '08/2026'
        }
    };
    res.render('Customer/my_account', {
        user: req.session.user,
        activePage: 'my-account', // For highlighting the sidebar link
        account: accountInfo
    });
});

// --- Data and Server Setup ---

const masterMeterData = [
    {
        id: 'SA-RYD-001',
        meterNumber: '65315101',
        billNumber: '294511223344',
        releaseDate: '2025-09-05',
        deadlineDate: '2025-09-25',
        periodStartDate: '2025-08-03',
        periodEndDate: '2025-09-02',
        periodStartReading: 11195,
        periodEndReading: 12345,
        status: 'Active',
        lastReading: '12,345 gal',
        totalReadings: '150,500 gal',
        location: 'Olaya District, Riyadh',
        buildingType: 'Commercial Building',
        amount: 'SAR 450.00',
        previousBillAmount: 0,
        lat: 24.7011,
        lng: 46.6835,
        paymentHistory: [
            { date: '2025-09-20', description: 'Monthly Bill', amount: '- SAR 450.00', status: 'Paid', type: 'Debit' },
            { date: '2025-08-20', description: 'Monthly Bill', amount: '- SAR 435.50', status: 'Paid', type: 'Debit' }
        ]
    },
    {
        id: 'SA-RYD-002',
        meterNumber: '65315102',
        billNumber: '294522334455',
        releaseDate: '2025-09-01',
        deadlineDate: '2025-09-20',
        periodStartDate: '2025-07-29',
        periodEndDate: '2025-08-28',
        periodStartReading: null,
        periodEndReading: null,
        status: 'Inactive',
        lastReading: 'N/A',
        totalReadings: '89,000 gal',
        location: 'Al Malaz, Riyadh',
        buildingType: 'Residential Building',
        amount: 'SAR 210.50',
        previousBillAmount: 0,
        lat: 24.6633,
        lng: 46.7381,
        paymentHistory: [
            { date: '2025-09-15', description: 'Final Bill', amount: '- SAR 210.50', status: 'Paid', type: 'Debit' }
        ]
    },
    {
        id: 'SA-RYD-003',
        meterNumber: '65315103',
        billNumber: '294533445566',
        releaseDate: '2025-09-10',
        deadlineDate: '2025-10-10',
        periodStartDate: '2025-06-09',
        periodEndDate: '2025-09-08',
        periodStartReading: 60890,
        periodEndReading: 67890,
        status: 'Active',
        lastReading: '67,890 gal',
        totalReadings: '750,000 gal',
        location: 'Diplomatic Quarter, Riyadh',
        buildingType: 'Government Building',
        amount: 'SAR 2,150.00',
        previousBillAmount: 0,
        lat: 24.6853,
        lng: 46.6325,
        paymentHistory: [
            { date: '2025-09-25', description: 'Quarterly Bill', amount: '- SAR 2,150.00', status: 'Paid', type: 'Debit' }
        ]
    },
    {
        id: 'SA-RYD-004',
        meterNumber: '65315104',
        billNumber: '294544556677',
        releaseDate: '2025-09-02',
        deadlineDate: '2025-09-22',
        periodStartDate: '2025-07-31',
        periodEndDate: '2025-08-30',
        periodStartReading: 48821,
        periodEndReading: 54321,
        status: 'Needs Attention',
        lastReading: '54,321 gal',
        totalReadings: '432,100 gal',
        location: 'King Abdullah Financial District, Riyadh',
        buildingType: 'Commercial Building',
        amount: 'SAR 1,812.20',
        previousBillAmount: 0,
        lat: 24.7631,
        lng: 46.6433,
        paymentHistory: [
             { date: '2025-09-18', description: 'Payment Attempt', amount: '- SAR 1,812.20', status: 'Failed', type: 'Debit' },
             { date: '2025-08-18', description: 'Monthly Bill', amount: '- SAR 1,750.00', status: 'Paid', type: 'Debit' }
        ]
    },
    {
        id: 'SA-RYD-005',
        meterNumber: '65315105',
        billNumber: '294555667788',
        releaseDate: '2025-09-07',
        deadlineDate: '2025-09-27',
        periodStartDate: '2025-08-06',
        periodEndDate: '2025-09-05',
        periodStartReading: 88765,
        periodEndReading: 98765,
        status: 'Active',
        lastReading: '98,765 gal',
        totalReadings: '995,400 gal',
        location: 'Al-Naseem, Riyadh',
        buildingType: 'Residential Building',
        amount: 'SAR 3,100.75',
        previousBillAmount: 0,
        lat: 24.7241,
        lng: 46.8229,
        paymentHistory: [
            { date: '2025-09-22', description: 'Monthly Bill', amount: '- SAR 3,100.75', status: 'Paid', type: 'Debit' }
        ]
    },
    {
        id: 'SA-RYD-006',
        meterNumber: '65315106',
        billNumber: '294566778899',
        releaseDate: '2025-09-12',
        deadlineDate: '2025-10-02',
        periodStartDate: '2025-08-11',
        periodEndDate: '2025-09-10',
        periodStartReading: 3567,
        periodEndReading: 4567,
        status: 'Active',
        lastReading: '4,567 gal',
        totalReadings: '210,800 gal',
        location: 'Al-Sulimaniah, Riyadh',
        buildingType: 'Residential Building',
        amount: 'SAR 385.50',
        previousBillAmount: 0,
        lat: 24.7050,
        lng: 46.7000,
        paymentHistory: [
            { date: '2025-09-28', description: 'Monthly Bill', amount: '- SAR 385.50', status: 'Paid', type: 'Debit' },
            { date: '2025-08-28', description: 'Monthly Bill', amount: '- SAR 370.00', status: 'Paid', type: 'Debit' }
        ]
    }
];

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

