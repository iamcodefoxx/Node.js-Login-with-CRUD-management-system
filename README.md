Node.js and MySQL - A complete login system with a user management system

=========================================================================

Create a .env file and initialize the environment variables below with your own credentials. I initialized them to some default values.

NODE_ENV=DEVELOPMENT

DB_LIMIT=10
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=mysupersecretpassword
DB_NAME=login

JWT_SECRET=mysupersecretpassword
JWT_EXPIRES_IN=90d
JWT_COOKIE_EXPIRES=90

=========================================================================
MySQL database schema:

See db_schema.txt
