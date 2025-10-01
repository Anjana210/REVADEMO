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
    // --- Data Processing for Dashboard ---
    const parseNumber = (str) => {
        if (typeof str !== 'string') return 0;
        return parseFloat(str.replace(/[^0-9.-]+/g, "")) || 0;
    };

    // 1. KPIs
    const totalMeters = masterMeterData.length;
    const activeMeters = masterMeterData.filter(m => m.status === 'Active').length;
    const totalConsumption = masterMeterData.reduce((sum, meter) => sum + parseNumber(meter.totalReadings), 0);
    const totalBilled = masterMeterData.reduce((sum, meter) => {
        const debitPayments = meter.paymentHistory.filter(p => p.type === 'Debit');
        return sum + debitPayments.reduce((subSum, p) => subSum + parseNumber(p.amount), 0);
    }, 0);

    // 2. Chart Data
    const consumptionByBuildingType = masterMeterData.reduce((acc, meter) => {
        const consumption = parseNumber(meter.totalReadings);
        acc[meter.buildingType] = (acc[meter.buildingType] || 0) + consumption;
        return acc;
    }, {});
    const buildingTypeChartData = Object.keys(consumptionByBuildingType).map(key => ({
        name: key,
        value: consumptionByBuildingType[key]
    }));

    const meterStatus = masterMeterData.reduce((acc, meter) => {
        acc[meter.status] = (acc[meter.status] || 0) + 1;
        return acc;
    }, {});
    const statusChartData = Object.keys(meterStatus).map(key => ({
        name: key,
        value: meterStatus[key]
    }));

    const consumptionPerMeterChartData = {
        ids: masterMeterData.map(m => m.id),
        values: masterMeterData.map(m => parseNumber(m.totalReadings))
    };

    // 3. Table Data
    const attentionMeters = masterMeterData.filter(m => m.status === 'Needs Attention');

    const recentPayments = masterMeterData
        .flatMap(meter => meter.paymentHistory.map(p => ({ ...p, meterId: meter.id })))
        .sort((a, b) => new Date(b.date) - new Date(a.date))
        .slice(0, 5); // Get the 5 most recent payments

    res.render('dashboards', {
        user: req.session.user,
        activePage: 'dashboard',
        kpis: {
            totalMeters,
            activeMeters,
            totalConsumption,
            totalBilled: Math.abs(totalBilled) // Ensure it's a positive number
        },
        charts: {
            buildingType: buildingTypeChartData,
            status: statusChartData,
            consumptionPerMeter: consumptionPerMeterChartData
        },
        attentionMeters,
        recentPayments,
        mapData: masterMeterData // Pass raw data for the map
    });
});


// --- NEW: Placeholder Routes for other pages ---
app.get('/billing', requireLogin, (req, res) => {
    res.render('billing', { user: req.session.user, activePage: 'billing' });
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

const masterMeterData = [
    { 
        id: 'SA-RYD-001', 
        status: 'Active', 
        lastReading: '12,345 gal', 
        totalReadings: '150,500 gal', 
        location: 'Olaya District, Riyadh', 
        buildingType: 'Commercial Building',
        amount: 'SAR 450.00',
        lat: 24.7011,
        lng: 46.6835,
        paymentHistory: [
            { date: '2025-09-20', description: 'Monthly Bill', amount: '- SAR 450.00', status: 'Paid', type: 'Debit' },
            { date: '2025-08-20', description: 'Monthly Bill', amount: '- SAR 435.50', status: 'Paid', type: 'Debit' }
        ]
    },
    { 
        id: 'SA-RYD-002', 
        status: 'Inactive', 
        lastReading: 'N/A', 
        totalReadings: '89,000 gal', 
        location: 'Al Malaz, Riyadh', 
        buildingType: 'Residential Building',
        amount: 'SAR 210.50',
        lat: 24.6633,
        lng: 46.7381,
        paymentHistory: [
            { date: '2025-09-15', description: 'Final Bill', amount: '- SAR 210.50', status: 'Paid', type: 'Debit' }
        ]
    },
    { 
        id: 'SA-RYD-003', 
        status: 'Active', 
        lastReading: '67,890 gal', 
        totalReadings: '750,000 gal', 
        location: 'Diplomatic Quarter, Riyadh', 
        buildingType: 'Government Building',
        amount: 'SAR 2,150.00',
        lat: 24.6853,
        lng: 46.6325,
        paymentHistory: [
            { date: '2025-09-25', description: 'Quarterly Bill', amount: '- SAR 2,150.00', status: 'Paid', type: 'Debit' }
        ]
    },
    { 
        id: 'SA-RYD-004', 
        status: 'Needs Attention', 
        lastReading: '54,321 gal', 
        totalReadings: '432,100 gal', 
        location: 'King Abdullah Financial District, Riyadh', 
        buildingType: 'Commercial Building',
        amount: 'SAR 1,812.20',
        lat: 24.7631,
        lng: 46.6433,
        paymentHistory: [
             { date: '2025-09-18', description: 'Payment Attempt', amount: '- SAR 1,812.20', status: 'Failed', type: 'Debit' },
             { date: '2025-08-18', description: 'Monthly Bill', amount: '- SAR 1,750.00', status: 'Paid', type: 'Debit' }
        ]
    },
    { 
        id: 'SA-RYD-005', 
        status: 'Active', 
        lastReading: '98,765 gal', 
        totalReadings: '995,400 gal', 
        location: 'Al-Naseem, Riyadh', 
        buildingType: 'Residential Building',
        amount: 'SAR 3,100.75',
        lat: 24.7241,
        lng: 46.8229,
        paymentHistory: [
            { date: '2025-09-22', description: 'Monthly Bill', amount: '- SAR 3,100.75', status: 'Paid', type: 'Debit' }
        ]
    }
];

// ... (your app.get('/') and other routes are here)

// UPDATED /meters route
app.get('/meters', requireLogin, (req, res) => {
    const { status } = req.query; 
    let filteredMeters = masterMeterData;
    if (status) {
        filteredMeters = masterMeterData.filter(meter => meter.status === status);
    }
    res.render('meters', { 
        user: req.session.user, 
        activePage: 'meters',
        meters: filteredMeters,
        activeFilter: status || 'All Meters' 
    });
});

// UPDATED /usage-details route
app.get('/usage-details', requireLogin, (req, res) => {
    // We map the data to match the expected format for this page, changing 'location' to 'locationName'
    const usageData = masterMeterData.map(m => ({...m, locationName: m.location, id: `#${m.id}`}));
    res.render('usage-details', { 
        user: req.session.user, 
        activePage: 'usage-details',
        data: usageData 
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
