const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs')
const passport = require('passport')

// User model
const User = require('../models/User');

//  Login Page
router.get('/login', (req, res) => res.render('login'));

//  Register Page
router.get('/register', (req, res) => res.render('register'));

//  Register Handle
router.post('/register', (req, res) => {
  const { name, email, password, password2 } = req.body;
  let errors = [];
  if(!name || !email || !password || !password2) {
    errors.push({msg: 'Please Fill in all fields.'})
  }
  //  Check that the pws match
  if(password != password2) {
    errors.push({msg: 'Passwords do not match.'});
  }
  //  Check that the pw length
  if(password.length < 6) {
    errors.push({msg: 'Password must be at least 6 characters.'})
  }
  if(errors.length > 0) {
    res.render('register', {
      errors,
      name,
      email,
      password,
      password2
    });
  }
  else {
    // Validation Pass
  User.findOne({ email: email }).then(user => {
    if(user) {
      errors.push({ msg: 'Email is already registered.'})
      //  User Exists
      res.render('register', {
        errors,
        name,
        email,
        password,
        password2,
      });
    }
    else {
      const newUser = new User({
        name,
        email,
        password
      });
      //  Hash password

      // generate a salt so you can create a hash
      bcrypt.genSalt(10, (err, salt) =>
        bcrypt.hash(newUser.password, salt, (err, hash) => {
          if(err) throw err;
          // Set password to hashed
          newUser.password = hash;
      newUser.save()
      .then(user => {
        req.flash('success_msg', 'You have successfully registered! ')
        res.redirect('/users/login')
      })
      .catch(err=> console.log(err))
    }));
    }
  });
  }
});
  // Login Handle
router.post('/login', (req, res, next) => {
  passport.authenticate('local', {
    successRedirect: '/dashboard',
    failureRedirect: '/users/login',
    failureFlash: true
  })(req, res, next)
});

  //  Logout Handle
  router.get('/logout', (req, res) => {
    req.logout();
    req.flash('success_msg', 'You are logged out');
    res.redirect('/users/login');

  })


module.exports = router;
