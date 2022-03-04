var windowLocation = window.location.pathname; 

switch(windowLocation){      
  case "/register":
    var registerJS = document.createElement('script');
    registerJS.type = "text/javascript";
    registerJS.src = "/js/register.js";
    document.body.append(registerJS);
    break;
  case "/auth/register":
    var registerJS = document.createElement('script');
    registerJS.type = "text/javascript";
    registerJS.src = "/js/register.js";
    document.body.append(registerJS);
    break;
  case "/login":
    var loginJS = document.createElement('script');
    loginJS.type = "text/javascript";
    loginJS.src = "/js/login.js";
    document.body.append(loginJS);
    break;
  case "/auth/login":
    var loginJS = document.createElement('script');
    loginJS.type = "text/javascript";
    loginJS.src = "/js/login.js";
    document.body.append(loginJS);
    break; 
  case "/auth/update-password":
    var passwordResetUpdateJS = document.createElement('script');
    passwordResetUpdateJS.type = "text/javascript";
    passwordResetUpdateJS.src = "/js/password-reset-update.js";
    document.body.append(passwordResetUpdateJS); 
}

// HAMBURGER MENU
const hamburger = document.querySelector(".hamburger");
const navMenu = document.querySelector(".nav-menu");

hamburger.addEventListener("click", () => {
    hamburger.classList.toggle("active");
    navMenu.classList.toggle("active");
});

document.querySelectorAll(".nav-link").forEach(n => n.addEventListener("click", () => {
    hamburger.classList.remove("active");
    navMenu.classList.remove("active");
}));
