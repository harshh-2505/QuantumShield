// Apply the saved colour theme before first paint (falls back to the system setting).
(function () {
  try {
    var t = localStorage.getItem("qs-theme");
    if (t === "light" || t === "dark") document.documentElement.setAttribute("data-theme", t);
  } catch (e) { /* storage unavailable: follow the system setting */ }
})();
