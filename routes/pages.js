const express = require("express");
const bcrypt = require("bcrypt");
const authController = require("../../controllers/auth")
const db = require("../../db.js");
const router = express.Router();

router.get("/", authController.isLoggedIn, (req, res) => {
  res.render("index", {title : "Home", user : req.user} );
});

// If user IS NOT logged in show the page otherwise redirect to the home page

router.get("/register", authController.isLoggedIn, (req, res) => {
  if(!req.user) res.render("register", {title: "Register", user : req.user});
  else res.redirect("/");
});

router.get("/login", authController.isLoggedIn, (req, res) => {
  if(!req.user) res.render("login", {title: "Login", user : req.user});
  else res.redirect("/");
});

router.get("/password-reset", authController.isLoggedIn, (req, res) => {
  if(!req.user) res.render("password-reset", {title: "Password Reset", user : req.user});
  else res.redirect("/");
});

router.get("/password-reset-update/:id:token", authController.isLoggedIn, async (req, res) => {
  if(!req.user){
    db.query("SELECT * FROM users WHERE id = ?", [req.params.id], async (error, results) => { 
      if((results != "") && (results[0].token != null) && (results[0].token_expires > Date.now()) ) {

        if ( req.params.token === results[0].token.toString() )
          res.render("password-reset-update", {title: "Password Reset Update", user : req.user, id: req.params.id, token: req.params.token, token_expires: results[0].token_expires, token_success: true} );

      } else{
        res.render("password-reset-update", {title: "Password Link Expired", user : req.user, token_success: false, message: "Password reset token is invalid or has expired."} );
      } 
    });
  // Log the user out for security reasons
  } else{
    res.cookie("jwt", "logout", {
      expires: new Date(Date.now() + 2*1000),
      httpOnly: true
    });

    res.status(200).redirect("/");
  }
    
});

router.get("/account-verification-message/:id:token", authController.isLoggedIn, async (req, res) => {
  if(!req.user){
    // Check that the user exists
    db.query("SELECT * FROM users WHERE id = ?", [req.params.id], async (error, results) => { 
      if( (results != "") && (results[0].token != null) ) {

        if( req.params.token === results[0].token.toString()) {
          db.query("UPDATE users SET token = ?, active = ? WHERE id = ?", [null, true, results[0].id],
          async (error, result) => {
            if(error) {
              throw error;
            } else {
              res.render("account-verification-message", {title: "Account Verification Message", user : req.user, success: true, message: "Account has been successfully verified."} );
            }
          });
        } else {
           res.render("account-verification-message", {title: "Account Verification Message", user : req.user, token_success: false, message: "Authentication token is invalid or has expired."} );
        }
          
      } else{
        res.render("account-verification-message", {title: "Account Verification Message", user : req.user, token_success: false, message: "Your account is already active please login."} );
      } 
    });
  // Log the user out for security reasons
  } else{
    res.cookie("jwt", "logout", {
      expires: new Date(Date.now() + 2*1000),
      httpOnly: true
    });
    return res.status(200).redirect("/");
  }
    
});

// If user IS logged in show the page otherwise redirect to the home page

router.get("/admin", authController.isLoggedIn, (req, res) => {
  if(req.user) res.render("admin", {title : "Admin", user : req.user } );
  else res.redirect("/login");
});

router.get("/profile", authController.isLoggedIn, (req, res) => {
  if(req.user) res.render("profile", {title : "Profile", user : req.user } );
  else res.redirect("/login");
});

// Output error page if route does not exists

router.get("*", authController.isLoggedIn, (req, res) => {
  res.render("error", {title: "Error 404 ", user : req.user});
});

module.exports = router;