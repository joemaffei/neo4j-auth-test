// load all the things we need
var LocalStrategy    = require('passport-local').Strategy;

// load up the user model
var User       = require('../app/models/user');

// load the auth variables
var configAuth = require('./auth'); // use this one for testing

module.exports = function(passport) {

    var db     = require("seraph")("http://localhost:7474");
    var bcrypt = require('bcrypt-nodejs');

    // =========================================================================
    // passport session setup ==================================================
    // =========================================================================
    // required for persistent login sessions
    // passport needs ability to serialize and unserialize users out of session

    // used to serialize the user for the session
    passport.serializeUser(function(user, done) {

        // this whole routine is a complete mess

        // PROBLEM! Sometimes 'user' is an array, sometimes a JSON object.
        // here's is a dirty workaround...

        if (!user.email) {
            var u = {
                email : user[0].email,
                password : user[0].password
            };
        } else {
            var u = user;
        };

        // is there a better way to pass 'id' than by querying the database ?!?!

        db.find({email:u.email},function(err,id){
            done(null,id);
        });
    });

    // used to deserialize the user
    passport.deserializeUser(function(id, done) {
        db.read(id, function(err, user) {
            done(err, user);
        });
    });

    // =========================================================================
    // LOCAL LOGIN =============================================================
    // =========================================================================
    passport.use('local-login', new LocalStrategy({
        // by default, local strategy uses username and password, we will override with email
        usernameField : 'email',
        passwordField : 'password',
        passReqToCallback : true // allows us to pass in the req from our route (lets us check if a user is logged in or not)
    },
    function(req, email2, password2, done) {
        if (email2)
            email2 = email2.toLowerCase(); // Use lower-case e-mails to avoid case-sensitive e-mail matching

        // asynchronous
        process.nextTick(function() {
            db.find({ email:email2 }, function(err, user) {

                // if there are any errors, return the error
                if (err)
                    return done(err);

                // if no user is found, return the message
                if (user=="")
                    return done(null, false, req.flash('loginMessage', 'No user found.'));

                if (!bcrypt.compareSync(password2, user[0].password))
                    return done(null, false, req.flash('loginMessage', 'Oops! Wrong password.'));

                // all is well, return user
                else
                    return done(null, user);
            });
        });

    }));

    // =========================================================================
    // LOCAL SIGNUP ============================================================
    // =========================================================================
    passport.use('local-signup', new LocalStrategy({
        // by default, local strategy uses username and password, we will override with email
        usernameField : 'email',
        passwordField : 'password',
        passReqToCallback : true // allows us to pass in the req from our route (lets us check if a user is logged in or not)
    },
    function(req, email2, password2, done) {
        if (email2)
            email2 = email2.toLowerCase(); // Use lower-case e-mails to avoid case-sensitive e-mail matching

        // asynchronous
        process.nextTick(function() {
            // if the user is not already logged in:
            if (!req.user) {

                //SOMETHING IS WRONG WITH THE NEXT LINE
                db.find({ email:email2 }, function(err, user) {

                    console.log(user, user!="");

                    // if there are any errors, return the error
                    if (err)
                        return done(err);

                    // check to see if theres already a user with that email
                    if (user!="") {
                        return done(null, false, req.flash('signupMessage', 'That email is already taken. (error 1)'));
                    } else {

                        // create the user
                        var newUser      = require('../app/models/user');

                        newUser.email    = email2;
                        newUser.password = bcrypt.hashSync(password2, bcrypt.genSaltSync(8), null);

                        newUser.save({email:newUser.email, password:newUser.password},function(err) {
                            if (err)
                                return done(err);

                            return done(null, newUser);
                        });
                    }

                });
            // if the user is logged in but has no local account...
            } else if ( !req.user.email ) {
                // ...presumably they're trying to connect a local account
                // BUT let's check if the email used to connect a local account is being used by another user
                db.find({ email:email2 }, function(err, user) {
                    if (err)
                        return done(err);
                    
                    if (user) {
                        return done(null, false, req.flash('loginMessage', 'That email is already taken. (error 2)'));
                        // Using 'loginMessage instead of signupMessage because it's used by /connect/local'
                    } else {
                        var user = req.user;
                        user.email = email2;
                        user.password = bcrypt.hashSync(password2, bcrypt.genSaltSync(8), null);
                        user.save({email:newUser.email, password:newUser.password},function (err) {
                            if (err)
                                return done(err);
                            
                            return done(null,user);
                        });                        
                    }
                });
            } else {
                // user is logged in and already has a local account. Ignore signup. (You should log out before trying to create a new account, user!)
                return done(null, req.user);
            }

        });

    }));

};
