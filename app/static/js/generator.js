/* Landing-page preview and the full generator. Passwords come from the server (Python `secrets`),
   are held in a JS variable only, and are never written to any browser storage. */
(function () {
  const { $, $$, h, api, toast, modal, copyText, paintMeter } = PV;
  const CATEGORIES = ['Social', 'Banking', 'Email', 'Work', 'Education', 'Shopping', 'Other']; // keep in sync with app/__init__.py

  // ---- landing preview ----
  const heroOut = $('#hero-out');
  if (heroOut) {
    let current = '';
    const run = async () => {
      try {
        const r = await api('POST', '/api/generate-password', { mode: 'random', length: 18 });
        current = r.password; heroOut.textContent = r.password;
        paintMeter($('#hero-meter'), $('#hero-label'), r);
      } catch (e) { heroOut.textContent = 'Could not generate right now.'; }
    };
    $('#hero-regen').addEventListener('click', run);
    $('#hero-copy').addEventListener('click', e => current && copyText(current, e.currentTarget));
    run();
    return;
  }

  // ---- generator page ----
  const out = $('#gen-output');
  if (!out) return;
  let current = '', mode = 'random', timer = null;
  const lens = { random: 20, pin: 6 };            // remember each mode's slider value
  const lenEl = $('#length'), lenOut = $('#length-out'), wordsEl = $('#words'), wordsOut = $('#words-out');

  function applyMode() {
    const isPin = mode === 'pin', isMem = mode === 'memorable';
    $('#opt-length').hidden = isMem;
    $('#opt-words').hidden = !isMem;
    $('#opt-chars').hidden = mode !== 'random';
    lenEl.min = isPin ? 4 : 8; lenEl.max = isPin ? 12 : 64;
    lenEl.value = lens[isPin ? 'pin' : 'random']; lenOut.textContent = lenEl.value;
  }

  async function generate() {
    const opts = { mode, exclude_ambiguous: $('#ambiguous').checked };
    if (mode === 'random') Object.assign(opts, { length: +lenEl.value, upper: $('#upper').checked, lower: $('#lower').checked, digits: $('#digits').checked, symbols: $('#symbols').checked });
    if (mode === 'pin') opts.length = +lenEl.value;
    if (mode === 'memorable') opts.words = +wordsEl.value;
    try {
      const r = await api('POST', '/api/generate-password', opts);
      current = r.password; out.textContent = r.password;
      paintMeter($('#gen-meter'), $('#gen-label'), { score: r.score, label: r.strength, entropy: r.entropy });
      $('#gen-entropy').textContent = 'Entropy ≈ ' + Math.round(r.entropy) + ' bits';
    } catch (e) { current = ''; out.textContent = e.message; $('#gen-entropy').textContent = ''; }
  }
  const soon = () => { clearTimeout(timer); timer = setTimeout(generate, 120); };

  $('#gen-tabs').addEventListener('click', e => {
    const b = e.target.closest('button'); if (!b) return;
    $$('#gen-tabs button').forEach(x => x.classList.toggle('on', x === b));
    mode = b.dataset.mode; applyMode(); generate();
  });
  lenEl.addEventListener('input', () => { lenOut.textContent = lenEl.value; lens[mode === 'pin' ? 'pin' : 'random'] = +lenEl.value; soon(); });
  wordsEl.addEventListener('input', () => { wordsOut.textContent = wordsEl.value; soon(); });
  $$('#gen-form input[type=checkbox]').forEach(cb => cb.addEventListener('change', () => {
    if (mode === 'random' && !['upper', 'lower', 'digits', 'symbols'].some(id => $('#' + id).checked)) {
      cb.checked = true; toast('Keep at least one character type selected.', 'info');
    }
    generate();
  }));
  $('#gen-form').addEventListener('submit', e => e.preventDefault());
  $('#gen-go').addEventListener('click', generate);
  $('#gen-copy').addEventListener('click', e => current && copyText(current, e.currentTarget));

  $('#gen-save').addEventListener('click', () => {
    if (!current) return;
    const title = h('input', { class: 'input', maxLength: 120, placeholder: 'e.g. GitHub' });
    const url = h('input', { class: 'input', placeholder: 'https://…' });
    const user = h('input', { class: 'input', autocomplete: 'off' });
    const cat = h('select', { class: 'input' }, CATEGORIES.map(c => h('option', { text: c, selected: c === 'Other' })));
    const err = h('div', { class: 'error-text' });
    const field = (l, el) => h('div', { class: 'field' }, h('label', { text: l }), el);
    const body = h('div', {}, field('Website / application', title), field('Website URL', url), field('Username / email', user), field('Category', cat), err);
    modal('Save to vault', body, [
      { label: 'Cancel', cls: 'btn-ghost', onClick: close => close() },
      { label: 'Save', cls: 'btn-primary', onClick: async close => {
        try {
          await api('POST', '/api/vault', { title: title.value, website_url: url.value, username: user.value, category: cat.value, password: current });
          close(); toast('Saved to your vault.', 'success');
        } catch (e) { err.textContent = (e.fields && Object.values(e.fields)[0]) || e.message; }
      } },
    ]);
  });

  applyMode(); generate();
})();
