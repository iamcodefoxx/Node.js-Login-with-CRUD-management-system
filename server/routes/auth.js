const express = require("express");
const authController = require("../controllers/authController");
const {check} = require("express-validator");
const router = express.Router();

// POST ROUTES  ============================================================

router.post("/register",
[
  check("first_name", "First name field cannot be empty.").not().isEmpty(),
  check("first_name", "First name must be less than 25 characters long.").isLength({min:0, max:25}),
  check("last_name", "Last name field cannot be empty.").not().isEmpty(),
  check("last_name", "Last name must be less than 25 characters long.").isLength({min:0, max:25}), 
  check("email", "The email you entered is invalid, please try again.").isEmail().normalizeEmail(),
  check("email", "Email address must be between 4-100 characters long, please try again.").isLength({min:4, max:100}).normalizeEmail(),
  check("password_confirm", "Password confirm field cannot be empty.").not().isEmpty(), 
  check("password", "Password must be between 8-60 characters long.").isLength({min:8, max:60}),
  check("password", "Password must include one lowercase character, one uppercase character, a number, and a special character.").matches(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?!.* )(?=.*[^a-zA-Z0-9]).{8,}$/, "i"),
  check("password", "Password don't match, please try again.").custom(( value, { req, res, next } ) => {
  if (value !== req.body.password_confirm) {
    throw new Error("Passwords don't match, please try again.");
  }else{
    return value;
  }
 })
], authController.register);

router.post("/login", authController.login);

router.get("/logout", authController.logout);

router.post("/update-password",
[ 
  check("password_confirm", "Password confirm field cannot be empty.").not().isEmpty(),
  check("password", "Password must be between 8-60 characters long.").isLength({min:8, max:60}),
  check("password", "Password must include one lowercase character, one uppercase character, a number, and a special character.").matches(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?!.* )(?=.*[^a-zA-Z0-9]).{8,}$/, "i"),
  check("password", "Password don't match, please try again.").custom(( value, { req, res, next } ) => {
  if (value !== req.body.password_confirm) {
    throw new Error("Passwords don't match, please try again.");
  }else{
    return value;
  }
 })
], authController.updatePassword);

router.post("/password-reset", authController.passwordReset);

router.post("/find-user", authController.isLoggedIn, authController.findUser);

router.post("/add-user", [
  check("first_name", "First name field cannot be empty.").not().isEmpty(),
  check("first_name", "First name must be less than 25 characters long.").isLength({min:0, max:25}),
  check("last_name", "Last name field cannot be empty.").not().isEmpty(),
  check("last_name", "Last name must be less than 25 characters long.").isLength({min:0, max:25}), 
  check("email", "The email you entered is invalid, please try again.").isEmail().normalizeEmail(),
  check("email", "Email address must be between 4-100 characters long, please try again.").isLength({min:4, max:100}).normalizeEmail(),
  check("password_confirm", "Password confirm field cannot be empty.").not().isEmpty(), 
  check("password", "Password must be between 8-60 characters long.").isLength({min:8, max:60}),
  check("password", "Password must include one lowercase character, one uppercase character, a number, and a special character.").matches(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?!.* )(?=.*[^a-zA-Z0-9]).{8,}$/, "i"),
  check("password", "Password don't match, please try again.").custom(( value, { req, res, next } ) => {
  if (value !== req.body.password_confirm) {
    throw new Error("Passwords don't match, please try again.");
  }else{
    return value;
  }
 })
], authController.isLoggedIn, authController.addUser);

router.post("/update-user/:id", authController.isLoggedIn, authController.updateUser);

module.exports = router;