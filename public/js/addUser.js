// Show/Hide password
const showPassword = document.querySelector("#show-password");
const passwordField = document.querySelector("#password");
const passwordMatchField = document.querySelector("#password-confirm");

showPassword.addEventListener("click", function (e) {
  if (showPassword.checked) {
    passwordField.setAttribute("type", "text");
    passwordMatchField.setAttribute("type", "text");
  }
  else {
    passwordField.setAttribute("type", "password");
    passwordMatchField.setAttribute("type", "password");
  }
})