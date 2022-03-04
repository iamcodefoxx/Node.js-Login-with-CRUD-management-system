const express = require("express");
const path = require("path");
const cookieParser = require("cookie-parser");
require("dotenv").config();

const app = express();

// Public folder
app.use(express.static('public'));

// Parse URL-encoded bodies (as sent by HTML forms)
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

app.use(cookieParser());

// Template engine
app.set("view engine", "ejs");

// Routes
app.use("/auth", require("./server/routes/auth"));
app.use("/", require("./server/routes/pages"));


const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server started on port${PORT}`);
});