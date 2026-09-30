// Runs in <head> so the saved theme is applied before first paint (no flash).
(function () {
  try {
    var t = localStorage.getItem('pv_theme');
    if (t === 'light' || t === 'dark') document.documentElement.setAttribute('data-theme', t);
  } catch (e) { /* storage blocked: stay on the default */ }
})();
