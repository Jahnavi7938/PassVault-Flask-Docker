/* Login + registration behaviour. The server re-validates everything; this is just feedback. */
(function () {
  const { $, $$, strength, paintMeter } = PV;

  // Stop double-submits and show a spinner.
  $$('#login-form, #register-form').forEach(form => {
    form.addEventListener('submit', () => {
      const btn = $('button[type=submit]', form);
      setTimeout(() => { btn.disabled = true; btn.classList.add('loading'); }, 0);
    });
  });

  const pw = $('#register-form #password');
  if (!pw) return;
  const rules = {
    len: v => v.length >= 12, upper: v => /[A-Z]/.test(v), lower: v => /[a-z]/.test(v),
    digit: v => /\d/.test(v), special: v => /[^A-Za-z0-9]/.test(v),
  };
  const confirm = $('#confirm_password'), msg = $('#confirm-msg');

  pw.addEventListener('input', () => {
    $$('#pw-rules li').forEach(li => li.classList.toggle('met', rules[li.dataset.rule](pw.value)));
    if (pw.value) paintMeter($('#pw-meter'), $('#pw-label'), strength(pw.value));
    else { paintMeter($('#pw-meter'), null, { score: 0, label: 'weak' }); $('#pw-label').textContent = 'Type a password to see how it scores.'; }
    checkMatch();
  });
  function checkMatch() {
    if (!confirm.value) { msg.textContent = ''; return; }
    msg.textContent = confirm.value === pw.value ? '' : "The passwords don't match.";
  }
  confirm.addEventListener('input', checkMatch);
})();
