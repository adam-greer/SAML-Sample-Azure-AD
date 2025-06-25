const express = require('express');
const path = require('path');
const fs = require('fs');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const SamlStrategy = require('passport-saml').Strategy;
const bcrypt = require('bcrypt');
const dotenv = require('dotenv');

dotenv.config();

const app = express();

app.use(express.urlencoded({ extended: true }));

// Setup views and static files
app.set('view engine', 'jade');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));

// Session setup (set secure: true if using HTTPS in production)
app.use(session({
  secret: process.env.MY_SESSION_SECRET || 'defaultsecret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false }
}));

app.use(passport.initialize());
app.use(passport.session());

// In-memory local users
const users = [
  {
    id: 1,
    username: 'admin',
    passwordHash: bcrypt.hashSync('password', 10),
    isAdmin: true,
  }
];

// Passport Local Strategy
passport.use(new LocalStrategy((username, password, done) => {
  const user = users.find(u => u.username === username);
  if (!user) return done(null, false, { message: 'Incorrect username.' });
  if (!bcrypt.compareSync(password, user.passwordHash)) return done(null, false, { message: 'Incorrect password.' });
  return done(null, user);
}));

// SAML Setup
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
      authType: 'saml',
    });
  }));
  samlEnabled = true;
  console.log('SAML login ENABLED');
} catch (e) {
  console.warn('SAML login DISABLED:', e.message);
}

// Serialize & Deserialize user
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => {
  if (user.username) {
    // local user
    const localUser = users.find(u => u.username === user.username);
    user.isAdmin = localUser ? localUser.isAdmin : false;
  } else if (user.email) {
    // SAML user - check JSON file
    const allUsers = loadUsers();
    const matched = allUsers.find(u => u.email === user.email);
    user.isAdmin = matched ? matched.isAdmin : false;
  } else {
    user.isAdmin = false;
  }
  done(null, user);
});

// Users JSON storage
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

// Middleware
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect('/login');
}

function ensureAdmin(req, res, next) {
  if (req.isAuthenticated() && req.user.isAdmin) return next();
  res.status(403).send('Unauthorized - Admins only');
}

// Routes

// Login page
app.get('/login', (req, res) => {
  res.render('login', { title: 'Login', samlEnabled });
});

// Local login form
app.get('/login/local', (req, res) => {
  res.render('login_local', { title: 'Local Login' });
});

// Local login POST
app.post('/login/local', passport.authenticate('local', {
  successRedirect: '/profile',
  failureRedirect: '/login/local'
}));

// SAML login and callback
if (samlEnabled) {
  app.get('/login/saml', passport.authenticate('saml', {
    failureRedirect: '/login',
    failureFlash: true
  }));

  app.post('/login/callback',
    passport.authenticate('saml', { failureRedirect: '/login' }),
    (req, res) => {
      const profile = req.user;

      // Add or update user in JSON store
      const userProfile = {
        email: profile.email || '',
        firstName: profile.firstName || '',
        lastName: profile.lastName || '',
        title: profile.title || '',
        displayName: profile.displayName || '',
        authType: 'saml',
        isAdmin: false // default false for SAML users
      };

      addOrUpdateUser(userProfile);

      req.session.userProfile = userProfile;
      res.redirect('/profile');
    });
} else {
  // If SAML disabled
  app.get('/login/saml', (req, res) => res.status(503).send('SAML login not configured'));
  app.post('/login/callback', (req, res) => res.status(503).send('SAML login not configured'));
}

// Profile page
app.get('/profile', ensureAuthenticated, (req, res) => {
  const userProfile = req.session.userProfile || req.user || {};
  res.render('profile', { title: 'Profile', user: userProfile });
});

// Users list (admin only)
app.get('/users', ensureAdmin, (req, res) => {
  const allUsers = loadUsers();
  const localUsers = users.map(u => ({
    email: u.username,
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

// Toggle admin flag for user (admin only)
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

// Admin: GET edit .env page
app.get('/admin/env', ensureAdmin, (req, res) => {
  const envFilePath = path.join(__dirname, '.env');
  const envConfig = dotenv.parse(fs.readFileSync(envFilePath));

  const filteredEnv = {
    SAML_CALLBACK_URL: envConfig.SAML_CALLBACK_URL || '',
    AZURE_AD_TENANT_ID: envConfig.AZURE_AD_TENANT_ID || '',
    AZURE_AD_ENTERPRISE_APP_SAML_Identifier: envConfig.AZURE_AD_ENTERPRISE_APP_SAML_Identifier || '',
    AZURE_AD_SAML_CERT_B64: envConfig.AZURE_AD_SAML_CERT_B64 || ''
  };

  res.render('admin_env', { envVars: filteredEnv, title: 'Edit SAML Configuration' });
});

// Admin: POST save .env changes
app.post('/admin/env/save', ensureAdmin, (req, res) => {
  try {
    const envFileContent = Object.entries(req.body)
      .map(([key, val]) => `${key}=${val}`)
      .join('\n');

    const envFilePath = path.join(__dirname, '.env');

    fs.writeFileSync(envFilePath, envFileContent, 'utf8');
    dotenv.config({ path: envFilePath, override: true });

    res.redirect('/profile');
  } catch (err) {
    console.error('Error saving .env file:', err);
    res.status(500).send('Failed to save .env file');
  }
});

// Logout route
app.get('/logout', (req, res, next) => {
  req.logout(err => {
    if (err) { return next(err); }
    res.redirect('/login');
  });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server started on port ${PORT}`));

