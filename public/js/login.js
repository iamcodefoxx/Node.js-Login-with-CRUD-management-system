const showPassword = document.querySelector("#show-password");
const passwordField = document.querySelector("#password");

showPassword.addEventListener("click", function (e) {
  if (showPassword.checked)
    passwordField.setAttribute("type", "text");
  else
    passwordField.setAttribute("type", "password");
})
