// show/hide password
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

// password strength
var strength = {
  0: "Worst",
  1: "Bad",
  2: "Weak",
  3: "Good",
  4: "Strong"
}

var password = document.querySelector("#password");
var text = document.querySelector("#password-strength-text");

password.addEventListener("input", function () {
  var val = password.value;
  var result = zxcvbn(val);

  if (val !== "") {
    text.innerHTML = "Strength: " + `<span id="score">${strength[result.score]}</span>`;
    switch (result.score) {
      case 1:
        password.style.borderColor = "red";
        document.querySelector("#score").style.color = "red";
        break;
      case 2:
        password.style.borderColor = "orange";
        document.querySelector("#score").style.color = "orange";
        break;
      case 3:
        password.style.borderColor = "gold";
        document.querySelector("#score").style.color = "gold";
        break;
      case 4:
        password.style.borderColor = "green";
        document.querySelector("#score").style.color = "green";
        break;
      default:
        password.style.borderColor = "lightgray";
    }
  } else {
    text.textContent = "";
  }
});