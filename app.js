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

//setup views and layout
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

// --- Users for local login ---
const users = [
  {
    id: 1,
    username: 'admin',
    // hashed password for 'password'
    passwordHash: bcrypt.hashSync('password', 10),
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
passport.deserializeUser((user, done) => done(null, user));

// --- Routes ---

// Unified login page
app.get('/login', (req, res) => {
  res.render('login', { title: 'Login', samlEnabled });
});


// Local login form

app.get('/login/local', (req, res) => {
  res.render('login_local', { title: 'Local Login' });
});

//profile

app.get('/profile', (req, res) => {
  if (!req.isAuthenticated()) return res.redirect('/login');

  // Use userProfile from session if you saved it there
  const userProfile = req.session.userProfile || {};
  console.log('Rengdering profile with user:', userProfile); 
  res.render('profile', { title: 'Profile', user: userProfile });
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

    // Use direct keys from the simplified user object (as set in SamlStrategy)
    const email = profile.email || '';
    const firstName = profile.firstName || '';
    const lastName = profile.lastName || '';
    const title = profile.title || ''; // only if you added title in SamlStrategy, otherwise empty
    const displayName = profile.displayName || ''; 

    const userProfile = { email, firstName, lastName, title, displayName };

    console.log('Saving to session:', userProfile);
    req.session.userProfile = userProfile;

    res.redirect('/profile');
  }
);

} else {
  app.get('/login/saml', (req, res) => res.status(503).send('SAML login not configured'));
  app.post('/login/callback', (req, res) => res.status(503).send('SAML login not configured'));
}


// KEEPING as backup until profile page works
// Protected profile route
/*app.get('/profile', (req, res) => {
  if (!req.isAuthenticated()) return res.redirect('/login');
  res.send(`
    <h1>Profile</h1>
    <p>Welcome, ${req.user.displayName || req.user.username || 'User'}!</p>
    <p><a href="/logout">Logout</a></p>
  `);
});
*/



// Logout route
app.get('/logout', (req, res) => {
  req.logout(() => {
    res.redirect('/login');
  });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server started on port ${PORT}`));

