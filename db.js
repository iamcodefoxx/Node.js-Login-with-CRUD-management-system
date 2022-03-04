const mysql = require("mysql");

require("dotenv").config();

const sqlConnection = mysql.createConnection({
  connectionLimit: process.env.DB_LIMIT,
  host           : process.env.DB_HOST,
  user           : process.env.DB_USER,
  password       : process.env.DB_PASSWORD,
  database       : process.env.DB_NAME
})

module.exports = sqlConnection;