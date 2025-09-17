const express = require('express');
const app = express();
const path = require('node:path');
const http = require('http');
const { Server } = require("socket.io");
const axios = require('axios');
const cors = require('cors');
// --- NEW: Import express-session ---
const session = require('express-session');

const port = process.env.PORT || 4000;

app.set('view engine', 'ejs');
app.use(cors({ origin: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));

// --- NEW: Configure session middleware ---
app.use(session({
  secret: 'a-secure-secret-key-for-revartix', // Use a strong, random secret
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false } // Set to true if using HTTPS
}));``

// --- Middleware to protect routes ---
const requireLogin = (req, res, next) => {
  if (!req.session.user) {
    return res.redirect('/');
  }
  next();
};

// --- Main Route (shows the login page) ---
app.get('/', (req, res) => {
  res.render('home');
});

// --- MODIFIED: Welcome Page Route ---
// Added 'requireLogin' middleware to protect this route
app.get('/welcome', requireLogin, async (req, res) => {
  const odooUrl = 'http://insiderevartix-contacts-22767503.dev.odoo.com/jsonrpc';
  const payload = {
    jsonrpc: "2.0",
    method: "call",
    params: {
      service: "object",
      method: "execute_kw",
      args: [
        "insiderevartix-contacts-22767503",
        2,
        "Revartix",
        "x_device_reading",
        "search_read",
        [[]],
        {
          fields: ["x_name", "x_studio_data_value", "x_studio_timestamp"]
        }
      ]
    }
  };

  try {
    const response = await axios.post(odooUrl, payload, {
      headers: { 'Content-Type': 'application/json' }
    });
    // Pass user from session to the template
    res.render('welcome', {
      records: response.data.result,
      user: req.session.user // <-- PASS USER OBJECT
    });
  } catch (error) {
    console.error("Error fetching data from Odoo:", error.message);
    res.send('<h1>Error</h1><p>Could not fetch data from the database.</p>');
  }
});

// --- MODIFIED: Login Route ---
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
      // Save user info in the session
      req.session.user = {
        name: response.data.result.name,
        uid: response.data.result.uid
      };
      res.redirect('/welcome');
    } else {
      res.redirect('/');
    }
  } catch (error) {
    console.error("Error connecting to Odoo:", error.message);
    res.send('<h1>Error</h1><p>Could not connect to the authentication server.</p>');
  }
});

// --- NEW: Logout Route ---
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.redirect('/welcome');
    }
    res.clearCookie('connect.sid'); // Clears the session cookie
    res.redirect('/');
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