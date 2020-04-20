The chefapi applications were written as demonstation code for using the chefapi. This code is in no way ready for production. Error handling, security considerations and some timing edge cases need to be dealt with to use this in production.  The login module should be replaced by some OATH2 handler and the rest of the chefapi code should be updated to deal with the changes. 

Handle login processing for the chefapi applications.  Verify the password of the user and return a JWT token.  All users login with a password of "password". Replace this authentication mechanism with something real.

Most of the code is based on https://www.sohamkamani.com/golang/2019-01-01-jwt-authentication/.

Login processing was originally written to use cookies. Cookies turned out to be too much
of a pain in the development environment.  The token is returned in the request body for
new tokens.  The token is used by passing it in the Authorization header.

The secret key is hard coded here and in the programs using the tokens.
