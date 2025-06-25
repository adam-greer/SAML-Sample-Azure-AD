const express = require('express');
const path = require('path');
const fs = require('fs');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const SamlStrategy = require('passport-saml').Strategy;
const bcrypt = require('bcrypt');
require('dotenv').config();

const app = express();

app.use(express.urlencoded({ extended: true }));

// Setup views and layout
app.set('view engine', 'jade');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));

// Session setup (adjust secret in production!)
app.use(session({
  secret: process.env.MY_SESSION_SECRET || 'defaultsecret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // set to true if using HTTPS
}));

app.use(passport.initialize());
app.use(passport.session());

// --- Users for local login (in-memory) ---
const users = [
  {
    id: 1,
    username: 'admin',
    passwordHash: bcrypt.hashSync('password', 10),
    isAdmin: true,
  }
];

// --- Passport Local Strategy ---
passport.use(new LocalStrategy((username, password, done) => {
  const user = users.find(u => u.username === username);
  if (!user) return done(null, false, { message: 'Incorrect username.' });
  if (!bcrypt.compareSync(password, user.passwordHash)) return done(null, false, { message: 'Incorrect password.' });
  return done(null, user);
}));

// --- Optional SAML Strategy Setup ---
let samlEnabled = false;
try {
  const cert = process.env.AZURE_AD_SAML_CERT_B64?.replace(/\\n/g, '\n');
  if (!cert || !process.env.SAML_CALLBACK_URL || !process.env.AZURE_AD_TENANT_ID || !process.env.AZURE_AD_ENTERPRISE_APP_SAML_Identifier) {
    throw new Error('SAML env vars missing');
  }
  passport.use(new SamlStrategy({
    callbackUrl: process.env.SAML_CALLBACK_URL,
    entryPoint: `https://login.microsoftonline.com/${process.env.AZURE_AD_TENANT_ID}/saml2`,
    issuer: process.env.AZURE_AD_ENTERPRISE_APP_SAML_Identifier,
    cert: cert,
    signatureAlgorithm: 'sha256'
  }, (profile, done) => {
    done(null, {
      id: profile.nameID,
      email: profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'],
      displayName: profile['http://schemas.microsoft.com/identity/claims/displayname'],
      firstName: profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname'],
      lastName: profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname'],
      title: profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/title'],
    });
  }));
  samlEnabled = true;
  console.log('SAML login ENABLED');
} catch (e) {
  console.warn('SAML login DISABLED:', e.message);
}

// --- Passport Serialize / Deserialize ---
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => {
  // Add admin logic here — check in JSON file or local users
  if (user.username) {
    // Local user
    const localUser = users.find(u => u.username === user.username);
    user.isAdmin = localUser ? localUser.isAdmin : false;
  } else if (user.email) {
    // SAML user, check JSON users
    const allUsers = loadUsers();
    const matched = allUsers.find(u => u.email === user.email);
    user.isAdmin = matched ? matched.isAdmin : false;
  } else {
    user.isAdmin = false;
  }

  done(null, user);
});

// --- Load/save users JSON ---
const usersFile = path.join(__dirname, 'users.json');

function loadUsers() {
  try {
    return JSON.parse(fs.readFileSync(usersFile));
  } catch {
    return [];
  }
}

function saveUsers(users) {
  fs.writeFileSync(usersFile, JSON.stringify(users, null, 2));
}

function addOrUpdateUser(user) {
  const users = loadUsers();
  const idx = users.findIndex(u => u.email === user.email);
  if (idx >= 0) {
    // Preserve existing isAdmin if missing in update
    if (typeof user.isAdmin === 'undefined') {
      user.isAdmin = users[idx].isAdmin || false;
    }
    users[idx] = { ...users[idx], ...user };
  } else {
    user.isAdmin = user.isAdmin || false;
    users.push(user);
  }
  saveUsers(users);
}

// --- Middleware to check admin ---
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect('/login');
}

function ensureAdmin(req, res, next) {
  if (req.isAuthenticated() && req.user.isAdmin) return next();
  res.status(403).send('Unauthorized - Admins only');
}

// --- Routes ---

// Unified login page
app.get('/login', (req, res) => {
  res.render('login', { title: 'Login', samlEnabled });
});

// Local login form
app.get('/login/local', (req, res) => {
  res.render('login_local', { title: 'Local Login' });
});

// Local login handler
app.post('/login/local', passport.authenticate('local', {
  successRedirect: '/profile',
  failureRedirect: '/login/local'
}));

// SAML login route and callback, if enabled
if (samlEnabled) {
  app.get('/login/saml', passport.authenticate('saml', {
    failureRedirect: '/login',
    failureFlash: true
  }));

  app.post('/login/callback',
    passport.authenticate('saml', { failureRedirect: '/login' }),
    (req, res) => {
      const profile = req.user;
      console.log('SAML profile:', profile);

      const email = profile.email || '';
      const firstName = profile.firstName || '';
      const lastName = profile.lastName || '';
      const title = profile.title || '';
      const displayName = profile.displayName || '';

      // Add authType and default isAdmin false if new user
      const userProfile = { email, firstName, lastName, title, displayName, authType: 'saml', isAdmin: false };

      addOrUpdateUser(userProfile);

      req.session.userProfile = userProfile;
      res.redirect('/profile');
    });
} else {
  app.get('/login/saml', (req, res) => res.status(503).send('SAML login not configured'));
  app.post('/login/callback', (req, res) => res.status(503).send('SAML login not configured'));
}

// Profile route
app.get('/profile', ensureAuthenticated, (req, res) => {
  // Use userProfile from session or fallback to req.user
  const userProfile = req.session.userProfile || req.user || {};
  res.render('profile', { title: 'Profile', user: userProfile });
});

// Users page — Admin only
app.get('/users', ensureAdmin, (req, res) => {
  const allUsers = loadUsers();
  // Also add local users (transform local users to match JSON user shape)
  const localUsers = users.map(u => ({
    email: u.username, // local users use username as email for simplicity
    firstName: '',
    lastName: '',
    title: '',
    displayName: u.username,
    authType: 'local',
    isAdmin: u.isAdmin || false,
  }));

  const combinedUsers = [...allUsers, ...localUsers];
  res.render('users', { users: combinedUsers, title: 'Users' });
});

// Admin toggle route for user
app.post('/users/:email/admin-toggle', ensureAdmin, (req, res) => {
  const email = req.params.email;
  const isAdmin = req.body.isAdmin === 'on';

  const allUsers = loadUsers();
  const userIndex = allUsers.findIndex(u => u.email === email);

  if (userIndex === -1) {
    // Check local users
    const localUserIndex = users.findIndex(u => u.username === email);
    if (localUserIndex !== -1) {
      users[localUserIndex].isAdmin = isAdmin;
      return res.redirect('/users');
    }
    return res.status(404).send('User not found');
  }

  allUsers[userIndex].isAdmin = isAdmin;
  saveUsers(allUsers);

  res.redirect('/users');
});

// admin route to edit env file

const envFilePath = path.join(__dirname, '.env');

app.get('/admin/env', ensureAdmin, (req, res) => {
  // Read .env file as text
  const envRaw = fs.readFileSync(envFilePath, 'utf8');

  // Parse lines to { key: value }
  const envVars = {};
  envRaw.split('\n').forEach(line => {
    const trimmed = line.trim();
    if (trimmed && !trimmed.startsWith('#')) {
      const [key, ...vals] = trimmed.split('=');
      envVars[key] = vals.join('=');
    }
  });

  res.render('admin_env', { title: '.env Editor', envVars });
});


// POST route to save changes to .env file
app.post('/admin/env/save', ensureAdmin, (req, res) => {
  // req.body contains key-value pairs from inputs
  const updatedEnv = Object.entries(req.body)
    .map(([key, val]) => `${key}=${val}`)
    .join('\n');

  fs.writeFileSync(envFilePath, updatedEnv, 'utf8');

  res.redirect('/admin/env');
});

// Logout route
app.get('/logout', (req, res) => {
  req.logout(() => {
    res.redirect('/login');
  });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server started on port ${PORT}`));

