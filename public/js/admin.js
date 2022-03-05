const overlay = document.getElementById("overlay");

document.querySelector("#show-modal-btn").addEventListener("click", () => {
    overlay.style.display = "block";
})

document.querySelector("#close-modal-btn").addEventListener("click", () => {
    overlay.style.display = "none";
})