/* Vault list (search, filter, view, delete) and the add/edit form. */
(function () {
  const { $, $$, h, api, toast, modal, confirmBox, bindMeter, paintMeter, strength, paintAvatars } = PV;
  const fmt = iso => iso ? new Date(iso).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' }) : 'never';
  const cap = s => s.charAt(0).toUpperCase() + s.slice(1);

  // Flash-style message carried over from a save/delete redirect.
  const params = new URLSearchParams(location.search);
  if (params.has('saved') || params.has('deleted')) {
    toast(params.has('saved') ? 'Saved.' : 'Credential deleted.', 'success');
    history.replaceState(null, '', location.pathname);
  }

  // ------------------------------------------------------------ list page
  const list = $('#vault-list');
  if (list) {
    const state = { q: '', filter: 'all', category: '' };
    let seq = 0, debounce = null;

    function row(it) {
      let host = '';
      try { host = it.website_url ? new URL(it.website_url).hostname : ''; } catch (e) {}
      return h('div', { class: 'vrow', 'data-item': it.id },
        h('div', { class: 'who' },
          h('div', { class: 'avatar', 'data-name': it.title, text: it.title.charAt(0).toUpperCase() }),
          h('div', {}, h('div', { class: 't', text: it.title }), h('div', { class: 'u', text: it.username || host || 'No username' }))),
        h('div', { class: 'pwcell' }, h('span', { class: 'mask', 'data-mask': '', text: '••••••••••••' }),
          h('div', { class: 'when', text: 'Updated ' + fmt(it.updated_at) })),
        h('div', { class: 'cat' }, h('span', { class: 'badge', text: it.category })),
        h('div', { class: 'str-cell' }, h('span', { class: 'badge badge-' + it.strength, text: cap(it.strength) })),
        h('div', { class: 'actions' },
          h('button', { class: 'btn btn-sm', type: 'button', 'data-view': it.id, text: 'View' }),
          h('button', { class: 'btn btn-sm', type: 'button', 'data-reveal': it.id, text: 'Reveal' }),
          h('button', { class: 'btn btn-sm', type: 'button', 'data-copy': it.id, text: 'Copy' }),
          h('a', { class: 'btn btn-sm', href: '/vault/edit/' + it.id, text: 'Edit' }),
          h('button', { class: 'btn btn-sm btn-danger', type: 'button', 'data-del': it.id, 'data-title': it.title, text: 'Delete' })));
    }

    async function load() {
      const mine = ++seq;
      const qs = new URLSearchParams({ q: state.q, filter: state.filter, category: state.category });
      try {
        const data = await api('GET', '/api/vault?' + qs);
        if (mine !== seq) return;              // a newer search already replaced this one
        list.textContent = '';
        if (!data.items.length) {
          const filtered = state.q || state.category || state.filter !== 'all';
          list.append(h('div', { class: 'empty' }, filtered ? 'Nothing matches that search.' : 'Your vault is empty. ',
            filtered ? null : h('a', { href: '/vault/add', text: 'Add your first password.' })));
        } else data.items.forEach(it => list.append(row(it)));
        $('#vault-count').textContent = data.count + (data.count === 1 ? ' credential' : ' credentials');
        paintAvatars(list);
      } catch (e) { toast(e.message, 'error'); }
    }

    $('#q').addEventListener('input', e => { clearTimeout(debounce); debounce = setTimeout(() => { state.q = e.target.value.trim(); load(); }, 220); });
    $('#cat').addEventListener('change', e => { state.category = e.target.value; load(); });
    $('#chips').addEventListener('click', e => {
      const chip = e.target.closest('.chip'); if (!chip) return;
      $$('.chip').forEach(c => c.classList.toggle('on', c === chip));
      state.filter = chip.dataset.filter; load();
    });

    list.addEventListener('click', async e => {
      const view = e.target.closest('[data-view]');
      if (view) return openDetails(view.dataset.view);
      const del = e.target.closest('[data-del]');
      if (del) {
        const ok = await confirmBox('Delete credential', 'Are you sure you want to permanently delete this credential?', 'Delete');
        if (!ok) return;
        try { await api('DELETE', '/api/vault/' + del.dataset.del); toast('Credential deleted.', 'success'); load(); }
        catch (err) { toast(err.message, 'error'); }
      }
    });

    async function openDetails(id) {
      try {
        const { item } = await api('GET', '/api/vault/' + id);
        const link = /^https?:\/\//.test(item.website_url || '')
          ? h('a', { href: item.website_url, target: '_blank', rel: 'noopener noreferrer', text: item.website_url }) : '-';
        const pw = h('div', { 'data-item': item.id },
          h('span', { class: 'mask', 'data-mask': '', text: '••••••••••••' }), ' ',
          h('button', { class: 'btn btn-sm', type: 'button', 'data-reveal': item.id, text: 'Reveal' }), ' ',
          h('button', { class: 'btn btn-sm', type: 'button', 'data-copy': item.id, text: 'Copy' }));
        const dl = h('dl', { class: 'dl' },
          h('dt', { text: 'Website' }), h('dd', {}, link),
          h('dt', { text: 'Username' }), h('dd', { text: item.username || '-' }),
          h('dt', { text: 'Password' }), h('dd', {}, pw),
          h('dt', { text: 'Strength' }), h('dd', {}, h('span', { class: 'badge badge-' + item.strength, text: cap(item.strength) })),
          h('dt', { text: 'Category' }), h('dd', { text: item.category }),
          h('dt', { text: 'Notes' }), h('dd', { class: 'pre', text: item.notes || '-' }),
          h('dt', { text: 'Created' }), h('dd', { text: fmt(item.created_at) }),
          h('dt', { text: 'Updated' }), h('dd', { text: fmt(item.updated_at) }),
          h('dt', { text: 'Password set' }), h('dd', { text: fmt(item.password_changed_at) }));
        modal(item.title, dl, [
          { label: 'Close', cls: 'btn-ghost', onClick: close => close() },
          { label: 'Edit', cls: 'btn-primary', onClick: () => { location.href = '/vault/edit/' + item.id; } },
        ]);
      } catch (e) { toast(e.message, 'error'); }
    }
    load();
  }

  // ------------------------------------------------------------ add / edit form
  const form = $('#item-form');
  if (form) {
    const pw = $('#password'), meter = $('#pw-meter'), lbl = $('#pw-label');
    const editing = form.dataset.mode === 'edit';
    bindMeter(pw, meter, lbl);
    // reset meter on load (edit page starts with an empty password box)
    paintMeter(meter, null, { score: 0, label: 'weak' });

    $('#gen-btn').addEventListener('click', async e => {
      e.currentTarget.disabled = true;
      try {
        const r = await api('POST', '/api/generate-password', { mode: 'random', length: 20, upper: true, lower: true, digits: true, symbols: true });
        pw.value = r.password; pw.type = 'text';
        const t = form.querySelector('[data-toggle-pw]'); if (t) t.textContent = 'Hide';
        paintMeter(meter, lbl, strength(r.password));
      } catch (err) { toast(err.message, 'error'); }
      e.currentTarget.disabled = false;
    });

    const showErrors = fields => $$('[data-err]', form).forEach(el => { el.textContent = (fields && fields[el.dataset.err]) || ''; });

    form.addEventListener('submit', async e => {
      e.preventDefault();
      showErrors({});
      const body = {
        title: $('#title').value, website_url: $('#website_url').value, username: $('#username').value,
        category: $('#category').value, notes: $('#notes').value,
      };
      if (pw.value || !editing) body.password = pw.value;   // blank on edit = keep the current one
      const btn = $('#save-btn'); btn.disabled = true; btn.classList.add('loading');
      try {
        if (editing) await api('PUT', '/api/vault/' + form.dataset.id, body);
        else await api('POST', '/api/vault', body);
        location.href = '/vault?saved=1';
      } catch (err) {
        showErrors(err.fields); toast(err.message, 'error');
        btn.disabled = false; btn.classList.remove('loading');
      }
    });

    const del = $('#delete-btn');
    if (del) del.addEventListener('click', async () => {
      const ok = await confirmBox('Delete credential', 'Are you sure you want to permanently delete this credential?', 'Delete');
      if (!ok) return;
      try { await api('DELETE', '/api/vault/' + form.dataset.id); location.href = '/vault?deleted=1'; }
      catch (err) { toast(err.message, 'error'); }
    });
  }
})();
