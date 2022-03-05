const mysql = require("mysql");
const db = require("../../db.js");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const saltRounds = 10;
const {resetPasswordEmail, activateAccountEmail} = require("../../mail.js");
const {promisify} = require("util");
const {validationResult} = require("express-validator");
var randomstring = require("randomstring");
require("dotenv").config();

// POST ROUTES CONTROLLER ========================================

function get_date(){
  let yourDate = new Date()
  const offset = yourDate.getTimezoneOffset();
  yourDate = new Date(yourDate.getTime() - (offset*60*1000));
  return yourDate.toISOString().split('T')[0]
}

exports.register = (req, res) => {
  const { first_name, last_name, password, password_confirm } = req.body;
  const member_since = get_date();
  var email = req.body.email;

  if(email === "@")
    email = undefined;

  // Use express validator to check for errors in user input
  const errors = validationResult(req);
  
  // Need to stringify and parse to access the data
  var allErrors = JSON.stringify(errors);
  var allParsedErrors = JSON.parse(allErrors);

  // If there are validation errors: return them to the user.
  if(!errors.isEmpty()){
    return res.render("register", { 
      title:"Register",
      allParsedErrors: allParsedErrors,
      first_name : first_name,
      last_name : last_name,
      email: email,
      password: password
    })
  }
  // If there isn't any validation errors: check if the email is already is in use
  db.query("SELECT * FROM users WHERE email = ?", [email], async (err, results) => {
    // Technical errors
    if (err) {
      console.log(err);
    // Let the user know the email already exists
    } else if (results != ""){
      return res.render("register", {title: "Register",
                                    success: false,
                                    message: "An account with that email already exists",
                                    first_name : first_name,
                                    last_name : last_name,
                                    email: email,
                                    password: password});
    // Create account
    } else {
      var token = randomstring.generate(20);

      bcrypt.hash(password, saltRounds, (err, hash) => {
        db.query("INSERT INTO users (first_name, last_name, email, password, token, member_since) VALUES (?,?,?,?,?,?)", [first_name, last_name, email, hash, token, member_since],
          async (err, results) => {
            if (err) {
              console.log(err);
            } else {
              db.query("SELECT * FROM users WHERE email = ?",[email], async (err, results) => {
                if (!err) {
                  const sent = activateAccountEmail(email, results[0].id, token);
                  if (sent != "0"){
                    return res.render("account-verification", {title: "Account Verification"});
                  }
                } else console.log(err)
              });
            }
        })//function
      });//bcrypt
    }
  })
}

exports.updatePassword = (req, res) => {
  
  const errors = validationResult(req);
  const { id, token, token_expires, password } = req.body;

  if(token_expires > Date.now()){
    // Need to stringify and parse to access the data
    var allErrors = JSON.stringify(errors);
    var allParsedErrors = JSON.parse(allErrors);

    if(!errors.isEmpty()){
      return res.render("password-reset-update", {
        title: "Password Reset Update",
        allParsedErrors: allParsedErrors,
        token: token,
        token_expires: token_expires,
        id: id,
        token_success: true
      })
    }

    bcrypt.hash(password, saltRounds, (err, hash) => {
      var data = { token: null, token_expires: null, password: hash};
      db.query("UPDATE users SET ? WHERE id = ?", [data, id], (err, result) => {
        if(!err) return res.render("password-reset-success", {title: "Password Reset Success"});
        else console.log(err);
      });
    });

  } else {
    return res.render("password-reset-update", {title: "Password Reset Update", token_success: false, message: "Password reset token is invalid or has expired" });
  }
}

exports.login = async (req, res) => {
  try{
    const { email, password } = req.body;
    // If email or password field is blank
    if(!email || !password){
      return res.status(400).render("login", {
        title: "Login",
        success: false,
        message: "Please provide an email and password"
      })
    }
    // Query the database
    db.query("SELECT * FROM users WHERE email = ?", [email], async (err, results) => {
      // If email is not in database OR password does not match
      if(results == "" || !(await bcrypt.compare(password, results[0].password.toString()))){
        return res.status(401).render("login", {
          title: "Login",
          success: false,
          message: "Email or password is incorrect."
        })
        // If account has not been verified
      } else if (results[0].status != "Active") {
        return res.render("login", {title: "Login", success: false, message: "This account is not verified"});
        // Else create a session cookie and allow the user to login
      } else {
        const id = results[0].id;

        const token = jwt.sign({ id: id}, process.env.JWT_SECRET, {
          expiresIn: process.env.JWT_EXPIRES_IN
        });

        const cookieOptions = {
          expires: new Date(
            Date.now() + process.env.JWT_COOKIE_EXPIRES * 24 * 60 * 60 * 1000
          ),
          httpOnly: true
        }
        res.cookie("jwt", token, cookieOptions);
        return res.status(200).redirect("/");
      }
    });
  }catch(err){
    console.log(err);
  }
}

exports.isLoggedIn = async (req, res, next) => {
  if(req.cookies.jwt){
    try{
      //1) verify the token
      const decoded = await promisify(jwt.verify)(req.cookies.jwt, process.env.JWT_SECRET);
      //2.) check if the user still exists
      db.query("SELECT * FROM users WHERE id = ?", [decoded.id], (err, result) => {
        if(!result){
          return next();
        }
        req.user = result[0];
        return next();
      })
    }catch(err){
      return next();
    }
  }else{
    next();
  }
}

exports.logout = async (req, res) => {
  res.cookie("jwt", "logout", {
    expires: new Date(Date.now() + 2*1000),
    httpOnly: true
  });
  return res.status(200).redirect("/");
}

exports.resetEmail = (req, res) => {
  var email = req.body.email;

  if(
    email === undefined ||
    email === "" ||
    email === null
  ){
    return res.render("password-reset", {title: "Password Reset", success: false, message : "Email field cannot be empty"})
  }

  db.query("SELECT * FROM users WHERE email = ?", [email] , (err, results) => {    
    if(results != "" && results[0].status != "Inactive") {
      // Generate a token 
      var token = randomstring.generate(20);
      // Set token expiration date
      const token_expires = Date.now() + 3600000;
      // Send user reset password email
      const sent = resetPasswordEmail(email, results[0].id, token);
      // If the password reset email was succesfully sent 
      if (sent != "0") {
        const data = { token: token, token_expires: token_expires};
        db.query("UPDATE users SET ? WHERE email = ?", [data, email], (err, results) => {
            if(!err) return res.render("password-reset-sent", {title: "Password Reset Sent"});
            else console.log(err);
        });
      // If the password reset email was not sent because of a technical error
      } else {
        return res.render("password-reset", {title: "Password Reset", success: false, message: "Something went wrong. Please try again!"});
      }
    // Email is not registered or verified so no email will be sent
    } else {
      return res.render("password-reset-sent", {title: "Password Reset Sent"});
    }
  });

}

exports.findUser = (req, res) => {
  let searchTerm = req.body.search;
  db.query("SELECT * FROM users WHERE first_name LIKE ? OR last_name LIKE ? OR email LIKE ?", ["%" + searchTerm + "%", "%" + searchTerm + "%", "%" + searchTerm + "%"], (err, rows) => {
    if(!err) return res.render("admin", {title: "Admin" , user : req.user, rows: rows});
    else console.log(err);
  });
}

exports.addUser = (req, res) => {
  const { first_name, last_name, password, password_confirm, admin } = req.body;
  const member_since = get_date();
  const status = "Active";
  var email = req.body.email;

  if(email === "@")
    email = undefined;

  // Use express validator to check for errors in user input
  const errors = validationResult(req);
  
  // Need to stringify and parse to access the data
  var allErrors = JSON.stringify(errors);
  var allParsedErrors = JSON.parse(allErrors);

  // If there are validation errors: return them to the user.
  if(!errors.isEmpty()){
    return res.render("add-user", { 
      title:"Add User",
      user : req.user,
      allParsedErrors: allParsedErrors,
      first_name : first_name,
      last_name : last_name,
      email: email,
      password: password
    })
  }

  // If there isn't any validation errors: check if the email is already is in use
  db.query("SELECT * FROM users WHERE email = ?", [email], async (err, results) => {
    // Technical error
    if (err) {
      console.log(err);
    // Email already exists
    } else if (results != ""){
      return res.render("add-user", {title: "Add User",
                              user : req.user,
                              success: false,
                              message: "An account with that email already exists",
                              first_name : first_name,
                              last_name : last_name,
                              email: email,
                              password: password});
    // Create account
    } else {
      bcrypt.hash(password, saltRounds, (err, hash) => {
        db.query("INSERT INTO users (first_name, last_name, email, password, member_since, status, admin) VALUES (?,?,?,?,?,?,?)", [first_name, last_name, email, hash, member_since, status, admin],
          async (err, results) => {
            if (!err) return res.render("add-user", {title: "Add User", user : req.user, success: true, message: "User account was created successfully"});
            else console.log(err)
        })// db function
      });//bcrypt
    }
  })
}

exports.updateUser = (req, res) => {
  const { first_name, last_name, admin } = req.body;
  var email = req.body.email;
  if(email === "@")
    email = undefined;

  db.query("UPDATE users SET first_name = ?, last_name = ?, email = ?, admin = ? WHERE id = ?", [first_name, last_name, email, admin, req.params.id],
    async (err, results) => {
      if (!err) {
        db.query("SELECT * FROM users WHERE id = ?",[req.params.id], (err, rows) => {
          if(!err) return res.render("edit-user", {title: "Edit User", user : req.user, success: true, message: "User has been updated", rows: rows});
          else console.log(err);
        });
      } else {
        console.log(err);
      }
  })// db function
}