/* Security page: colours the health ring and can re-run the check via the API. */
(function () {
  const { $, $$, api, toast, h } = PV;
  const ring = $('#ring');
  function paint(pct) {
    ring.style.setProperty('--pct', pct);
    ring.style.setProperty('--ringc', pct >= 70 ? 'var(--ok)' : pct >= 40 ? 'var(--warn)' : 'var(--bad)');
  }
  paint(Number(ring.dataset.pct));

  $('#rerun').addEventListener('click', async e => {
    const btn = e.currentTarget; btn.disabled = true;
    try {
      const r = await api('GET', '/api/security-report');
      $$('[data-stat]').forEach(el => { el.textContent = r[el.dataset.stat]; });
      $('#health-num').textContent = r.health + '%'; paint(r.health);
      const list = $('#reco'); list.textContent = '';
      r.recommendations.forEach(t => list.append(h('li', { text: t })));
      toast('Check complete.', 'success');
      if (r.weak_items.length + r.reused_items.length + r.old_items.length) toast('Reload the page to refresh the detail lists.', 'info');
    } catch (err) { toast(err.message, 'error'); }
    btn.disabled = false;
  });
})();
