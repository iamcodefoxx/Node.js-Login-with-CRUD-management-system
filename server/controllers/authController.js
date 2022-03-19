const mysql = require("mysql");
const db = require("../../db.js");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const saltRounds = 10;
const mail = require("../../mail.js");
const {promisify} = require("util");
const {validationResult} = require("express-validator");
var randomstring = require("randomstring");
require("dotenv").config();

function get_date(){
  let yourDate = new Date()
  const offset = yourDate.getTimezoneOffset();
  yourDate = new Date(yourDate.getTime() - (offset*60*1000));
  return yourDate.toISOString().split('T')[0]
}


// REGISTER -------------------------------------------------------


exports.register = (req, res) => {
  const { first_name, last_name, email, password, password_confirm } = req.body;
  const member_since = get_date();

  // GRAB ANY ERRORS FROM EXPRESS VALIDATOR
  const errors = validationResult(req);
  // STRINGIFY TO PARSE THE DATA
  const allErrors = JSON.stringify(errors);
  const allParsedErrors = JSON.parse(allErrors);
   // OUTPUT VALIDATION ERRORS IF ANY
  if(!errors.isEmpty()){
    return res.render("register", {
      title: "Register | Loaves Fishes Computers",
      allParsedErrors: allParsedErrors,
      first_name : first_name,
      last_name : last_name,
      email : email,
      password : password
    })
  }

  db.query("SELECT email FROM user WHERE email = ?", [email], async (err, results) => {
    // CHECK IF EMAIL ALREADY EXISTS IN DATABASE
    if (!err && results != "") {
      return res.render("register", {title: "Register | Loaves Fishes Computers",
                              success: false,
                              message: "An account with that email already exists",
                              first_name : first_name,
                              last_name : last_name,
                              email: email,
                              password: password});
    // ELSE CREATE A NEW USER
    } else if(!err && results[0] === undefined){
        var token = randomstring.generate(20);
        bcrypt.hash(password, saltRounds, (err, hash) => {
          db.query("INSERT INTO user (first_name, last_name, email, password, token, member_since) VALUES (?,?,?,?,?,?)", [first_name, last_name, email, hash, token, member_since],
            async (err, results) => {
              if (!err) {
                mail.activateAccountEmail(email, results.insertId, token, (err, data) => {
                  if(!err) return res.render("account-verification", {title: "Account Verification | Loaves Fishes Computers"});
                  else console.log(err.message);
                });
              // DATABASE ERROR
              } else { console.log(err.message) }
          })//function
        });//bcrypt
    // DATABASE ERROR
    } else{ console.log(err.message); } 
   });
}


// LOGIN -------------------------------------------------------


exports.login = async (req, res) => {
  const {email, password} = req.body;

  // VALIDATE THAT EMAIL AND/OR PASSWORD ARE NOT EMPTY STRINGS
  if(!email || !password){
    return res.status(400).render("login", {
      title:"Login",
      success: false,
      message: "Please provide a username and password"
    })
  }

  db.query("SELECT * FROM user WHERE email = ?", [email], async (err, results) => {
    // IF EMAIL IS NOT IN THE DATABASE OR PASSWORDS DO NOT MATCH
    if(!err && (results == "" || !(await bcrypt.compare(password, results[0].password.toString())))){
      return res.status(401).render("login", {title:"Login", success: false,  message: "Email or password is incorrect"});
    // ELSE IF ACCOUNT IS INACTIVE
    } else if (!err && results[0].status === "Inactive") {
      return res.render("login", {title: "Login", success: false, message: "This account is not verified"});
    // ELSE ALLOW USER TO LOGIN
    } else if (!err && results[0].status === "Active"){
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
    // DATABASE ERROR
    } else{
      console.log(err.message)
    }
  });
}

// IS USER LOGGED IN? -------------------------------------------------------


exports.isLoggedIn = async (req, res, next) => {
  if(req.cookies.jwt){
    try{
      //1) verify the token
      const decoded = await promisify(jwt.verify)(req.cookies.jwt, process.env.JWT_SECRET);
      //2.) check if the user still exists
      db.query("SELECT * FROM user WHERE id = ?", [decoded.id], (err, result) => {
        if(!result){
          return next();
        }
        req.user = result[0];
        return next();
      })
    }catch(err){
      return next();
    }
  }else{ next(); }
}


// LOGOUT -------------------------------------------------------


exports.logout = async (req, res) => {
  res.cookie("jwt", "logout", {
    expires: new Date(Date.now() + 2*1000),
    httpOnly: true
  });
  return res.status(200).redirect("/");
}


// PASSWORD RESET -------------------------------------------------------


exports.passwordReset = (req, res) => {
  var email = req.body.email;
  const pattern = /^[a-zA-Z0-9\-_]+(\.[a-zA-Z0-9\-_]+)*@[a-z0-9]+(\-[a-z0-9]+)*(\.[a-z0-9]+(\-[a-z0-9]+)*)*\.[a-z]{2,4}$/;

  // CHECK FOR EMAIL VALIDATION
  if(
    email === undefined ||
    email === "" ||
    email === null
  ){
    return res.render("password-reset", {title: "Password Reset", success: false, message : "Email field cannot be empty"})
  } else if(!pattern.test(email)){
    return res.render("password-reset", {title: "Password Reset", success: false, message : "Email is invalid"})
  }

  // CHECK IF EMAIL EXISTS  
  db.query("SELECT id, email FROM user WHERE email = ?", [email] , (err, results) => {    
    // EMAIL FOUND
    if(!err && results[0] != undefined) {
      var id = results[0].id;
      // GENERATE TOKEN 
      var token = randomstring.generate(20);
      // SET EXPIRATION DATE
      const token_expires = Date.now() + 3600000;
      const data = { token: token, token_expires: token_expires};
      // SEND USER EMAIL TO RESET PASSWORD
      db.query("UPDATE user SET ? WHERE email = ?", [data, email], (err, results) => {
        if(!err) {
          mail.resetPasswordEmail(email, id, token, (err, data) => {
            if(!err) return res.render("password-reset-sent", {title: "Password Reset Sent | Loaves Fishes Computers"});  
            else console.log(err.message);
          });
        // DATABASE ERROR
        } else console.log(err.message);
      }); 
    // EMAIL WAS NOT FOUND (USER DOES NOT EXIST)
    } else if(!err && results[0] === undefined) {
       return res.render("password-reset-sent", {title: "Password Reset Sent"});
    // DATABASE ERROR
    } else {
      console.log(err.message)
    }
  });
}


// UPDATE PASSWORD -------------------------------------------------------


exports.updatePassword = (req, res) => {
  const { id, token, token_expires, password } = req.body;

  // CHECK THAT TOKEN IS NOT EXPIRED
  if(token_expires > Date.now()){
    // GRAB ANY ERRORS FROM EXPRESS VALIDATOR
    const errors = validationResult(req);
    // STRINGIFY TO PARSE THE DATA
    var allErrors = JSON.stringify(errors);
    var allParsedErrors = JSON.parse(allErrors);
     // OUTPUT VALIDATION ERRORS IF ANY
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
    // UPDATE THE PASSWORD
    bcrypt.hash(password, saltRounds, (err, hash) => {
      var data = { token: null, token_expires: null, password: hash};
      db.query("UPDATE user SET ? WHERE id = ?", [data, id], (err, result) => {
        if(!err) return res.render("password-reset-success", {title: "Password Reset Success"});
        else console.log(err.message);
      });
    });
  } else {
    return res.render("password-reset-update", {title: "Password Reset Update", token_success: false, message: "Password reset token is invalid or has expired" });
  }
}


// ADMIN CRUD SYSTEM ======================================================================================


// FIND USER -------------------------------------------------------

exports.findUser = (req, res) => {
  let searchTerm = req.body.search;
  db.query("SELECT * FROM user WHERE (first_name LIKE ? OR last_name LIKE ? OR email LIKE ?) && status != 'Deleted'", ["%" + searchTerm + "%", "%" + searchTerm + "%", "%" + searchTerm + "%"], (err, rows) => {
    if(!err) return res.render("admin", {title: "Admin" , user : req.user, rows: rows});
    else console.log(err);
  });
}


// ADD USER -------------------------------------------------------


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
  db.query("SELECT * FROM user WHERE email = ?", [email], async (err, results) => {
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
        db.query("INSERT INTO user (first_name, last_name, email, password, member_since, status, admin) VALUES (?,?,?,?,?,?,?)", [first_name, last_name, email, hash, member_since, status, admin],
          async (err, results) => {
            if (!err) return res.render("add-user", {title: "Add User", user : req.user, success: true, message: "User account was created successfully"});
            else console.log(err)
        })// db function
      });//bcrypt
    }
  })
}


// UPDATE USER -------------------------------------------------------


exports.updateUser = (req, res) => {
  const { first_name, last_name, admin } = req.body;
  var email = req.body.email;
  if(email === "@")
    email = undefined;

  db.query("UPDATE user SET first_name = ?, last_name = ?, email = ?, admin = ? WHERE id = ?", [first_name, last_name, email, admin, req.params.id],
    async (err, results) => {
      if (!err) {
        db.query("SELECT * FROM user WHERE id = ?",[req.params.id], (err, rows) => {
          if(!err) return res.render("edit-user", {title: "Edit User", user : req.user, success: true, message: "User has been updated", rows: rows});
          else console.log(err);
        });
      } else {
        console.log(err);
      }
  })// db function
}