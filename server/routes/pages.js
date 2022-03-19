const express = require("express");
const bcrypt = require("bcrypt");
const db = require("../../db.js");
const authController = require("../controllers/authController")

const router = express.Router();

// FUNCTION TO CHECK FOR INTERNET EXPLORER ============================================

function checkBrowser(headers){
  var ba = ["Chrome","Firefox","Safari","Opera","MSIE","Trident", "Edge"];
  var b, ua = headers['user-agent'];
  for(var i=0; i < ba.length;i++){
    if(ua.indexOf(ba[i]) > -1){
      b = ba[i];
      break;
    }
  }
  // IF INTERNET EXPLORER IS BEING USED RETURN TRUE OTHERWISE RETURN FALSE
  if(b === "MSIE" || b === "Trident") return true;
  else return false
}

// GET ROUTES ==============================================================

router.get("/", authController.isLoggedIn, (req, res) => {
  if(!checkBrowser(req.headers))
    return res.render("index", {title: "Home", user : req.user} );
  else
    return res.render("unsupported", {title: "Home", user : req.user});
});

router.get("/register", authController.isLoggedIn, (req, res) => {
  // If user IS NOT logged in show the page otherwise redirect to the home page
  if(!req.user && !checkBrowser(req.headers))
    res.render("register", {title: "Register", user : req.user});
  else
    res.redirect("/");
});

router.get("/login", authController.isLoggedIn, (req, res) => {
  if(!req.user && !checkBrowser(req.headers))
    return res.render("login", {title: "Login", user : req.user});
  else
    return res.redirect("/");
});

router.get("/password-reset", authController.isLoggedIn, (req, res) => {
  if(!req.user && !checkBrowser(req.headers))
    return res.render("password-reset", {title: "Password Reset", user : req.user} );
  else
    return res.redirect("/");
});

router.get("/account-verification-message/:id:token", authController.isLoggedIn, async (req, res) => {
  if(!req.user && !checkBrowser(req.headers)){
    // Check that the user exists
    db.query("SELECT * FROM user WHERE id = ?", [req.params.id], async (err, results) => { 
      if((results != "") && (results[0].token != null)) {
        if( req.params.token === results[0].token.toString()) {
          db.query("UPDATE user SET token = ?, status = ? WHERE id = ?", [null, "Active", results[0].id],
          async (err, result) => {
            if(!err) return res.render("account-verification-message", {title: "Account Verification Message", user : req.user, success: true, message: "Account has been successfully verified."} );
            else console.log(err.message)
          });
        } else {
           return res.render("account-verification-message", {title: "Account Verification Message", user : req.user, message: "Authentication token is invalid or has expired."} );
        }
      } else{
        return res.render("account-verification-message", {title: "Account Verification Message", user : req.user, message: "Your account is already active please login."} );
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

router.get("/password-reset-update/:id:token", authController.isLoggedIn, async (req, res) => {
  if(!req.user && !checkBrowser(req.headers)){
    db.query("SELECT * FROM user WHERE id = ?", [req.params.id], async (err, results) => { 
      if((results != "") && (results[0].token != null) && (results[0].token_expires > Date.now()) ) {
        if (req.params.token === results[0].token.toString() )
          return res.render("password-reset-update", {title: "Password Reset Update", user : req.user, id: req.params.id, token: req.params.token, token_expires: results[0].token_expires, token_success: true} );
      } else{
        return res.render("password-reset-update", {title: "Password Link Expired", user : req.user, token_success: false, message: "Password reset token is invalid or has expired."} );
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

// USER MUST BE LOGGED IN TO USE THESE ROUTES

router.get("/profile", authController.isLoggedIn, (req, res) => {
  // If user IS logged in show the page otherwise redirect to the home page
  if(req.user && !checkBrowser(req.headers)) 
    return res.render("profile", {title: "Profile", user : req.user} );
  else 
    return res.redirect("/login");
});


// ADMIN CRUD SYSTEM =======================================================================

// USER MUST BE LOGGED IN AND BE AN ADMIN TO USE THESE ROUTES

router.get("/admin", authController.isLoggedIn, (req, res) => {
  if(req.user.admin === "Yes" && !checkBrowser(req.headers)) {
    db.query("SELECT * FROM user WHERE status != 'Deleted'", (err, rows) => {
      if(!err) return res.render("admin", {title: "Admin" , user : req.user, rows: rows});
      else console.log(err);
    });
  }
  else return res.redirect("/login");
});

router.get("/add-user", authController.isLoggedIn, (req, res) => {
  if(req.user.admin === "Yes" && !checkBrowser(req.headers))
    return res.render("add-user", {title : "Add User", user : req.user } );
  else 
    return res.redirect("/login");
});

router.get("/edit-user/:id", authController.isLoggedIn, (req, res) => {
  if(req.user.admin === "Yes" && !checkBrowser(req.headers)) {
    db.query("SELECT * FROM user WHERE id = ?",[req.params.id], (err, rows) => {
      if(!err) return res.render("edit-user", {title: "Edit User" , user : req.user, rows: rows});
      else console.log(err);
    });
  }
  else res.redirect("/login");
});

router.get("/view-user/:id", authController.isLoggedIn, (req, res) => {
  if(req.user.admin === "Yes" && !checkBrowser(req.headers)){
    db.query("SELECT * FROM user WHERE id = ?",[req.params.id], (err, rows) => {
      if(!err) return res.render("view-user", {title: "View User" , user : req.user, rows: rows})
      else console.log(err);
    });
  }
  else return res.redirect("/login");
});

router.get("/del-user/:id", authController.isLoggedIn, (req, res) => {
  if(req.user.admin === "Yes" && !checkBrowser(req.headers)) {
    db.query("UPDATE user SET email = ?, status = ? WHERE id = ?", [null, "Deleted", req.params.id], (err, rows) => {
      if(!err) return res.redirect("/admin");
      else console.log(err);
    });
  }
  else return res.redirect("/login");
});

router.get("*", authController.isLoggedIn, (req, res) => {
  // Output error page if route does not exists
  return res.render("error", {title: "Error 404 ", user : req.user});
});

module.exports = router;