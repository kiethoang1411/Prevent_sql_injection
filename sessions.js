'use strict';

// Import express
const express = require('express');
const ejs = require('ejs');

// Import express-session, it stores many different sessions including cookie 
// Client-session stores in cookie
const session = require('express-session');

// The body parser
const bodyParser = require("body-parser");

// The mysql library
const mysql = require('mysql2');

// Instantiate an express app
const app = express();

// Import Check-password-strength package 
const { passwordStrength } = require('check-password-strength');

// Import bcrypt package 
const bcrypt = require('bcrypt');

// Salt Rounds
const saltRounds = 10;

// Import Https
const https = require('https');

// Import Files
const fs = require('fs');

// Import CSP Helmet
const csp = require('helmet-csp');

// Set the view engine
app.set('view engine', 'ejs');

// Read key and certificate from files
const privateKey = fs.readFileSync('key.pem', 'utf8');
const certificate = fs.readFileSync('cert.pem', 'utf8');
const passphrase = '987654321';

// Create credentials
const credentials = { key: privateKey, cert: certificate, passphrase: passphrase };

function isUserNameValid(username) {
  /* 
    Usernames can only have: 
    - Lowercase Letters (a-z)
    - Upercase
    - Numbers (0-9)
    - Dots (.)
    - Underscores (_)
  */
  if (/^[a-zA-Z0-9._]+$/.test(username)) return 1;
  else return 0;
}

function isPasswordValid(password) {
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

  if (passwordRegex.test(password)) return 1;
  else return 0;
}

function checkPasswordStrength(password) {
  const { value } = passwordStrength(password);
  if (value === 'Too Short') {
    return 0; // password is too weak
  } else if (value === 'Weak') {
    return 1; // password is weak
  } else if (value === 'Medium') {
    return 2; // password is medium strength
  } else if (value === 'Strong') {
    return 3; // password is strong
  } else {
    return 0; // password is too weak (default case)
  }
}

async function limitFailedLoginAttempts(req, res, next) {
	const ipAddress = req.ip;
  
	// Check if the IP address is already in the failedAttempts dictionary
	if (failedAttemptsDictionary[ipAddress]) {
	  const failedAttempts = failedAttemptsDictionary[ipAddress].attempts;
	  const lastAttemptTimestamp = failedAttemptsDictionary[ipAddress].timestamp;
  
	  // Check if the user has made more than 3 failed attempts in the last 3 minutes
	  if (failedAttempts >= 3 && Date.now() - lastAttemptTimestamp < 3 * 60 * 1000) {
		const countdown = Math.ceil((3 * 60 * 1000 - (Date.now() - lastAttemptTimestamp)) / 1000);
		console.log(`Too many failed login attempts. Please wait ${countdown} seconds and try again.`);
		return res.send(`Too many failed login attempts. Please wait ${countdown} seconds and try again.`);
	  }
	}
  
	// Call the next middleware function
	next();
  }
  
const failedAttemptsDictionary = {};

// Connect to the database
const mysqlConn = mysql.createConnection({
  host: 'localhost',
  user: 'appaccount',
  password: 'apppass',
  database: 'users'
});


// Needed to parse the request body
// Note that in version 4 of express, express.bodyParser() was
// deprecated in favor of a separate 'body-parser' module.
app.use(bodyParser.urlencoded({ extended: true }));

// The session settings middleware	
app.use(session({
  cookieName: 'session',
  secret: 'session_secret_key',
  duration: 1000 * 60 * 10, // 10 minutes
  activeDuration: 1000 * 60 * 10, // 10 minutes
  cookie: {
    httpOnly: true, // Make session cookies HTTPOnly
    secure: true,
    ephemeral: true
  }
}));

app.use(
	csp({
	  directives: {
		defaultSrc: ["'self'"],
		scriptSrc: ["'self'"],
		styleSrc: ["'self'"],
		fontSrc: ["'self'"],
		imgSrc: ["'self'"],
		connectSrc: ["'self'"],
		frameSrc: ["'self'"],
		objectSrc: ["'self'"],
	  },
	})
  );

// The default page
// @param req - the request
// @param res - the response
app.get("/", function(req, res) {

  // Is this user logged in?
  if (req.session.username) {
    // Yes!
    res.redirect('/dashboard');
  }
  else {
    // No!
    res.render('loginpage');
  }

});

// The login page
// @param req - the request
// @param res - the response

app.get('/dashboard', function(req, res) {
  if (req.session.username) {
    // Construct the query
    // Construct the query 
    let query = "SELECT username, session, info FROM appusers WHERE username = ? AND session = ?";


    // Query the DB for the user
    mysqlConn.query(query, [req.session.username, req.sessionID], function(err, qResult) {
      if (err) throw err;

      if (qResult.length > 0) {
        // User found with active session, display their info
        let user = qResult[0];
        res.render('dashboard', { username: user.username, info: user.info });
      } else {
        // User not found or session expired
        res.send({ success: false, message: 'User not found or session expired' });
      }
    });
  }
  else {
    // Please log in or create an account
    res.send({ success: false, message: 'Please log in or create an account' });
  }
});

// Render register page
app.get('/register', function(req, res) {
  res.render('register');
});


// Register
app.post('/register', async function(req, res) {
  // Get the username and password data from the form
  let userName = req.body.username;
  let password = req.body.password;

  // Validate the username and password
  if (isUserNameValid(userName) && isPasswordValid(password)) {
    // Check if the user already exists
    let checkQuery = "SELECT username FROM appusers WHERE username = ?";
    mysqlConn.query(checkQuery, [userName], async function(err, qResult) {
      if (err) throw err;

      if (qResult.length > 0) {
        // User already exists, show an error message
        res.send("User already exists!");
      } else {
        // Check the password strength
        const passwordStrengthValue = checkPasswordStrength(password);
        if (passwordStrengthValue >= 2) { // Adjust this value based on desired minimum password strength
          // Hash the password
          const hashedPassword = await bcrypt.hash(password, saltRounds);

          // Insert the new user into the appusers table with the hashed password
          let insertQuery = "INSERT INTO appusers (username, password, session) VALUES (?, ?, 'not logged in')";
          mysqlConn.query(insertQuery, [userName, hashedPassword], function(err, insertResult) {
            if (err) throw err;

            // Registration successful, redirect to the login page
            res.redirect('/');
          });
        } else {
          // Password is not strong enough
          res.send("Your password is not strong enough. Please choose a stronger password.");
        }
      }
    });
  } else {
    // Invalid username or password format
    res.send("Invalid username or password format. Please follow the specified requirements.");
  }
});

// The login script
// @param req - the request
// @param res - the response
// The login script
app.post('/login', limitFailedLoginAttempts, async function(req, res) {
	const ipAddress = req.ip;
  
	// Get the username and password data from the form
	let userName = req.body.username;
	let password = req.body.password;
  
	// Construct the query
	let query = "SELECT * FROM appusers WHERE username = ?";
  
	// Query the DB for the user
	mysqlConn.query(query, [userName], async function(err, qResult) {
	  if (err) throw err;
  
	  if (qResult.length > 0) {
		console.log("User found in the database");
		console.log("Stored password hash: ", qResult[0].password);
  
		// Compare the provided password with the stored hashed password
		const match = await bcrypt.compare(password, qResult[0].password);
		console.log("Password match: ", match);
  
		if (match) {
		  // Update the session attribute in the appusers table
		  let updateQuery = "UPDATE appusers SET session = ? WHERE username = ?";
		  mysqlConn.query(updateQuery, [req.sessionID, userName], function(err, updateResult) {
			// Login succeeded! Set the session variable and send the user to the dashboard
			req.session.username = userName;
			res.redirect('/dashboard');
		  });
		} else {
		  // If passwords do not match, increment the failed attempts for this IP address
		  if (failedAttemptsDictionary[ipAddress]) {
			failedAttemptsDictionary[ipAddress].attempts++;
		  } else {
			failedAttemptsDictionary[ipAddress] = { attempts: 1, timestamp: Date.now() };
		  }
		  // Show an error message
		  res.send("<b>Wrong</b>");
		}
	  } else {
		// If no matches have been found, we are done
		res.send("<b>Wrong</b>");
	  }
	});
  });  

// The logout function
// @param req - the request
// @param res - the response
app.get('/logout', function(req, res) {
  // Update the session attribute in the appusers table
  let updateQuery = "UPDATE appusers SET session = 'not logged in' WHERE username = ?";
  mysqlConn.query(updateQuery, [req.session.username], function(err, updateResult) {
    if (err) throw err;

    // Kill the session
    req.session.destroy();

    res.redirect('/');
  });
});

https.createServer(credentials, app).listen(3000, function() {
  console.log('Server running on https://localhost:3000');
});



