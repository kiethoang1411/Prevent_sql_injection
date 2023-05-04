# Prevent_sql_injection

CPSC_455_Web_Security 

Requirement for assignment:

1. Add a "session" attribute to the appusers table.
2. When the user logs in, store the session ID in the "session" attribute of the user's record.  Please do not make any other changes to the database.
3. When the user navigates to the site, the back-end (1) checks if the user is logged in and has an active session; and (2) if so, the back-end looks up the user record based on the session ID and shows a simple welcome page showing the user's name and the contents of the "info" column.   Otherwise, the user is directed to a login/create account page.
4. When the user logs out, the session ID is deleted from the user's record (or is replaced with some place holder value such as "not logged in".
5. Add an option to allow users to register (i.e., add their user name and password)
5. Use the node.js's bcrypt package to securely store and verify passwords (in the SQL dabatabse).  You can also find a very simple sample file here Download file here.
6. Use node.js's check-password-strength checker package Links to an external site. to check whether the user's password is strong according to OWASP 10 requirements covered in class.
7. Add a self-signed HTTPs certificate.
8. Configure the client-sessions package [I using express-session instead of client-session] to have the session expire after 10 mins inactivity (which the program already uses).
9. Add CSP protection and make session cookies HTTPOnly to ensure some protection against XSS.
10. Make sure that the webapp has a privilege-restricted database account.
