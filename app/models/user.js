// load the things we need
var db = require("seraph")("http://localhost:7474");
var model = require('seraph-model');
var bcrypt   = require('bcrypt-nodejs');

var User = model(db,'user');

// define the schema for our user model
User.schema = {email:String,password:String};
/*
    local            : {
        email        : String,
        password     : String
    },
    facebook         : {
        id           : String,
        token        : String,
        email        : String,
        name         : String
    },
    twitter          : {
        id           : String,
        token        : String,
        displayName  : String,
        username     : String
    },
    google           : {
        id           : String,
        token        : String,
        email        : String,
        name         : String
    }
};
*/

/*
// generating a hash
User.generateHash = function(password) {
    return bcrypt.hashSync(password, bcrypt.genSaltSync(8), null);
};

// checking if password is valid
User.validPassword = function(password) {
    return bcrypt.compareSync(password, this.password);
};
*/

// create the model for users and expose it to our app
module.exports = User;