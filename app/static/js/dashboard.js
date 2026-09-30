/* Dashboard: time-of-day greeting. Reveal/copy on recent items is handled globally in main.js. */
(function () {
  const g = PV.$('#greeting');
  if (!g) return;
  const hr = new Date().getHours();
  const part = hr < 5 ? 'Still up' : hr < 12 ? 'Good morning' : hr < 18 ? 'Good afternoon' : 'Good evening';
  g.textContent = hr < 5 ? part + ', ' + g.dataset.name + '?' : part + ', ' + g.dataset.name;
})();
