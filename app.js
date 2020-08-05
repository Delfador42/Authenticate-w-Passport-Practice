//jshint esversion:6
//project: secrets-LoginAuth

require('dotenv').config()
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require('ejs');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-find-or-create');
const FacebookStrategy = require('passport-facebook');

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));

app.use(session({
  //Secret is a string of characters used to compute the hash
  secret: "Our little secret.",
  resave: false,
  // complies with laws that require permission before setting cookies
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", {
  useNewUrlParser: true,
  useUnifiedTopology: true
});
mongoose.set("useCreateIndex",true);

const userSchema = new mongoose.Schema({
  email : { type: String, require: true, index:true, unique:true,sparse:true},
  password: { type: String, require:true },
  username: {type: String, sparse:true},
  googleId: {type: String, sparse:true},
  facebookId: {type: String, sparse:true},
  submitedUserSecret: {type: String, sparse:true}
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);



const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

//The serializeUser and deserializeUser sets the data in the cookie
// made of information of the user such as userID
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

//Configure Google Strategy oauth2.0
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    //The callback URL must be the same url you set on the google dashboard
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo'
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

//Configure Facebook Strategy
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


//Facebook login handle
app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
});

//Google login handle
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/secrets',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
});

//Home login or register
app.get('/', function(req, res) {
  res.render('home');
});

//login
app.get('/login', function(req, res) {
  res.render('login');
});

//register
app.get('/register', function(req, res) {
  res.render('register');
});

app.get('/logout',function(req, res){
  req.logout();
  res.redirect('/');
});


app.get('/secrets', function(req,res){
User.find({'submitedUserSecret':{$ne: null}}, function(err,foundUser){
  if(err){
    console.log(err);
  }else{
    if(foundUser){
      res.render("secrets", {usersWithSecrets: foundUser});
    }
  }
});
});


app.get('/submit', function(req,res){
//authenticate that the user is logged in
if(req.isAuthenticated()){
  res.render('submit');
}else{
  res.redirect('/login');
}
});

//Allow users to submit their own secrets
app.post('/submit', function(req,res){
  const submittedSecret = req.body.secret;
  //note that passport logs the users details in the req
  console.log(req.user.id);
    User.findById(req.user.id, function(err, foundUser){
      if(err){
        console.log(err);
      }else{
        if(foundUser){
          foundUser.submitedUserSecret = submittedSecret;
          foundUser.save(function(){
            res.redirect('/secrets');
          });
        }
      }
    });
  });


//post user registration information into a user database
// app.post("/register", function(req, res) {

// User.register({username: req.body.username}, req.body.password, function(err, user){
//     if(err){
//       console.log(err);
//       res.redirect("/register");
//     }else{
//       //creates a cookie that that saves the user login session, and
//       //is deleted once the browser is exited ending the session
//       passport.authenticate("local")(req, res, function(){
//         res.redirect("/secrets");
//       });
//     }
//   });
// });


app.post("/login", function(req, res) {

  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

req.login(user, function(err){
  if(err){
    console.log(err);
  }else{
    passport.authenticate("local")(req, res, function(){
      res.redirect("/secrets");
    });
  }
});

});


//listen
app.listen(3000, function() {
  console.log("server started on port 3000");
})
