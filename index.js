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
// Home Page Route
// Home Page Route
app.get('/home', requireCustomer, (req, res) => {
    // In a real app, you would fetch this summary data from your database
    const kpiData = {
        currentBalance: '125.50',
        nextBillDue: '130.00',
        lastPaidDate: 'December 15, 2025',
        nextBillDate: 'January 20, 2026'
    };

    const usageGraphData = {
        labels: ['Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'],
        values: [4200, 4500, 4300, 4600, 4400, 4750]
    };

    const recentTransactions = [
        { date: '2025-12-15', description: 'Payment Received', amount: '-125.50' },
        { date: '2025-11-20', description: 'Monthly Bill', amount: '130.00' },
        { date: '2025-10-20', description: 'Monthly Bill', amount: '115.00' }
    ];

    res.render('Customer/home', {
        user: req.session.user,
        activePage: 'home',
        kpis: kpiData,
        graphData: usageGraphData,
        transactions: recentTransactions
    });
});


// Billing Page Route
app.get('/billing', requireCustomer, (req, res) => {
    // Expanded invoice data to populate the modal
    const invoicesData = [
        { 
            id: 'INV-00125', issueDate: '2025-10-05', dueDate: '2025-10-25', amount: '465.50', status: 'Due',
            // ... (details for this invoice would go here)
        },
        { 
            id: 'INV-00124', issueDate: '2025-09-05', dueDate: '2025-09-25', amount: '450.00', status: 'Paid',
            // --- Detailed data for the modal ---
            customerName: 'Customer User Demo',
            address: '1234 Olaya St, Al-Sulimaniah, Riyadh 12245',
            accountNumber: '987-654-3210',
            meterNumber: '65315101',
            billingUnits: 'Gallons',
            meterDiameter: '2 inches',
            consumptionStartDate: '2025-08-03',
            startRead: '11195',
            consumptionEndDate: '2025-09-02',
            endRead: '12345',
            beforeVAT: '391.30',
            vatPercentage: '15%',
            vatValue: '58.70',
            afterVAT: '450.00',
            consumptionValue: '380.00',
            serviceFee: '5.30',
            meterTariff: '6.00',
            totalAmount: '450.00'
        },
        { 
            id: 'INV-00123', issueDate: '2025-08-05', dueDate: '2025-08-25', amount: '435.50', status: 'Paid',
            // ... (details for this invoice would go here)
        }
    ];

    const paymentHistoryData = [
        { id: 'TXN-98765', date: '2025-09-20', description: 'Payment for INV-00124', amount: 'SAR 450.00', method: 'Mada', receiptUrl: '#' },
        { id: 'TXN-98764', date: '2025-08-19', description: 'Payment for INV-00123', amount: 'SAR 435.50', method: 'Visa', receiptUrl: '#' }
    ];

    const planDetails = {
        type: 'Postpaid Residential',
        totalDue: '465.50',
        rates: [
            { tier: '1 - 15 m³', rate: '0.10' }, { tier: '16 - 30 m³', rate: '1.00' },
            { tier: '31 - 45 m³', rate: '3.00' }, { tier: '46 - 60 m³', rate: '4.00' },
            { tier: '> 60 m³', rate: '6.00' }
        ]
    };

    res.render('Customer/billing', { 
        user: req.session.user, 
        activePage: 'billing',
        invoices: invoicesData,
        paymentHistory: paymentHistoryData,
        plan: planDetails
    });
});

// Reports Page Route
app.get('/reports', requireCustomer, (req, res) => {
    // In a real app, you would fetch this from the database
    const metersList = masterMeterData.map(m => ({ id: m.id, location: m.location }));

    const pastInvoices = [
        { id: 'INV-00124', issueDate: '2025-09-05', amount: 'SAR 450.00', status: 'Paid', downloadUrl: '#' },
        { id: 'INV-00123', issueDate: '2025-08-05', amount: 'SAR 435.50', status: 'Paid', downloadUrl: '#' },
        { id: 'INV-00122', issueDate: '2025-07-05', amount: 'SAR 445.00', status: 'Paid', downloadUrl: '#' },
        { id: 'INV-00121', issueDate: '2025-06-05', amount: 'SAR 420.75', status: 'Paid', downloadUrl: '#' }
    ];

    res.render('Customer/reports', { 
        user: req.session.user, 
        activePage: 'reports',
        meters: metersList,
        invoices: pastInvoices
    });
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
    // In a real application, you would fetch this data from your database
    const usageChartData = {
        weekly: {
            labels: ['Week 1', 'Week 2', 'Week 3', 'Week 4'],
            values: [1150, 1200, 1100, 1180]
        },
        monthly: {
            labels: ['July', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'],
            values: [4500, 4200, 4600, 4400, 4700, 4800]
        },
        yearly: {
            labels: ['2023', '2024', '2025'],
            values: [55000, 59000, 61000]
        }
    };

    res.render('Customer/usage-details', {
        user: req.session.user,
        activePage: 'usage-details',
        chartData: usageChartData
    });
});

// Alerts & Notifications Page Route
app.get('/alerts', requireCustomer, (req, res) => {
    // In a real app, this data would come from a database or a real-time events system
    const alertsData = [
        {
            type: 'overdue',
            title: 'Overdue Bill Alert',
            timestamp: 'October 2, 2025',
            message: 'Your bill for invoice INV-00124 (SAR 450.00) is now 7 days overdue. Please make a payment to avoid service disruption.',
            link: '/billing',
            linkText: 'Pay Now'
        },
        {
            type: 'usage',
            title: 'Abnormal Usage Detected',
            timestamp: 'September 30, 2025',
            message: 'We detected continuous water flow at meter SA-RYD-004 for over 6 hours, which may indicate a leak. We recommend checking your property for potential issues.',
            link: '/meters',
            linkText: 'View Meter Details'
        },
        {
            type: 'service',
            title: 'Planned Service Interruption',
            timestamp: 'September 28, 2025',
            message: 'Please be advised of a planned service interruption in the Olaya District for system maintenance on October 10, 2025, from 1:00 AM to 5:00 AM.',
        }
    ];

    // Calculate KPIs
    const kpiData = {
        total: alertsData.length,
        urgent: alertsData.filter(a => a.type === 'overdue' || a.type === 'usage').length,
        info: alertsData.filter(a => a.type === 'service').length
    };

    res.render('Customer/alerts', {
        user: req.session.user,
        activePage: 'alerts',
        alerts: alertsData,
        kpis: kpiData // Pass KPI data to the page
    });
});

// Support & Help Page Route
app.get('/support', requireCustomer, (req, res) => {
    // In a real app, you would fetch FAQs from a database or CMS
    const faqData = [
        {
            question: 'How is my water bill calculated?',
            answer: 'Your water bill is calculated based on a tiered system known as block rates. The price per cubic meter increases as your consumption moves into higher tiers. You can view the specific rates for your plan on the Billing & Payments page.'
        },
        {
            question: 'What should I do if I suspect a water leak?',
            answer: 'If you suspect a leak, first check your property for any visible signs like dripping faucets or wet spots. You can also monitor your meter for continuous activity. If you confirm a leak or see an abnormal usage alert, we recommend contacting a certified plumber immediately.'
        },
        {
            question: 'How can I update my payment information?',
            answer: 'You can manage your payment methods on the Settings page. From there, you can add a new credit/debit card or bank account, set a default payment method, and remove old ones.'
        }
    ];

    res.render('Customer/support', {
        user: req.session.user,
        activePage: 'support',
        faqs: faqData
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

