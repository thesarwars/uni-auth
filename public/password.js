/*
 * Password fields, enhanced (auth-plan.md section 7.4: progressive enhancement). Without this
 * file every screen still works: the rules are listed, and the server checks them on submit.
 * With it:
 *   - every password field gets a show/hide button;
 *   - the rules list ticks each rule as it is met, with the same tests the server applies
 *     (src/credentials/password.service.ts checkPassword);
 *   - a strength meter, which only advises: it never blocks a password the policy accepts;
 *   - "Confirm password" says whether the two match;
 *   - the code field is shown as one box per digit, and its button waits for every digit.
 * The only script these pages may run (Content-Security-Policy: script-src 'self').
 */
(function () {
  'use strict';

  var TESTS = {
    min_length: function (pw, n) {
      return Array.from(pw).length >= n;
    },
    uppercase: function (pw) {
      return /\p{Lu}/u.test(pw);
    },
    digit_or_symbol: function (pw) {
      return /[^\p{L}\s]/u.test(pw);
    },
  };
  var LEVELS = ['', 'Weak', 'Fair', 'Good', 'Strong'];

  // Show / hide, on every password field that has a reveal button.
  document.querySelectorAll('button[data-reveal]').forEach(function (button) {
    var input = document.getElementById(button.getAttribute('data-reveal'));
    if (!input) return;
    button.hidden = false;
    button.addEventListener('click', function () {
      var show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      button.setAttribute('aria-pressed', String(show));
      button.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
      input.focus();
    });
    // A password left visible is hidden again before the form leaves the page.
    if (input.form) {
      input.form.addEventListener('submit', function () {
        input.type = 'password';
      });
    }
  });

  // The code: the real input stays (it takes the typing, the paste and the autofill) but sits
  // invisibly over one box per digit, which show what it holds and where the next digit goes.
  var code = document.getElementById('code');
  var wrap = code && code.parentElement;
  if (code && wrap && wrap.classList.contains('code')) {
    var length = Number(code.getAttribute('data-length')) || 6;
    var boxes = document.createElement('div');
    boxes.className = 'boxes';
    boxes.setAttribute('aria-hidden', 'true');
    for (var i = 0; i < length; i++) boxes.appendChild(document.createElement('span'));
    wrap.insertBefore(boxes, code.nextSibling);
    wrap.classList.add('boxed');
    var submit = code.form && code.form.querySelector('button[value="verify_code"]');
    var show = function () {
      code.value = code.value.replace(/\D/g, '').slice(0, length);
      var digits = code.value.split('');
      Array.prototype.forEach.call(boxes.children, function (box, i) {
        box.textContent = digits[i] || '';
        box.classList.toggle('at', i === Math.min(digits.length, length - 1));
      });
      if (submit) submit.disabled = digits.length < length;
    };
    code.addEventListener('input', function () {
      // A new digit is a new attempt: the last one's red marks go.
      wrap.removeAttribute('data-invalid');
      show();
    });
    code.addEventListener('focus', function () {
      wrap.classList.add('focused');
    });
    code.addEventListener('blur', function () {
      wrap.classList.remove('focused');
    });
    show();
    if (document.activeElement === code) wrap.classList.add('focused');
  }

  var rules = document.getElementById('rules');
  var password = document.getElementById('password');
  if (!rules || !password || password.getAttribute('autocomplete') !== 'new-password') return;
  var items = Array.prototype.slice.call(rules.querySelectorAll('li[data-rule]'));
  var strength = document.getElementById('strength');
  var confirm = document.getElementById('confirm');
  var match = document.getElementById('match');

  function score(pw) {
    if (!pw) return 0;
    var length = Array.from(pw).length;
    var kinds = [/\p{Ll}/u, /\p{Lu}/u, /\p{N}/u, /[^\p{L}\p{N}\s]/u].filter(function (r) {
      return r.test(pw);
    }).length;
    var s = 0;
    if (length >= 8) s++;
    if (length >= 12) s++;
    if (length >= 16) s++;
    if (kinds >= 3) s++;
    if (kinds === 4) s++;
    if (/(.)\1\1/u.test(pw)) s--; // aaa
    if (/^(?:password|passw0rd|qwerty|letmein|welcome|123456|abc123)/i.test(pw)) s = 0;
    return s <= 1 ? 1 : s === 2 ? 2 : s === 3 ? 3 : 4;
  }

  function update() {
    var pw = password.value;
    var allMet = true;
    items.forEach(function (li) {
      var test = TESTS[li.getAttribute('data-rule')];
      var met = test ? test(pw, Number(li.getAttribute('data-value'))) : false;
      if (!met) allMet = false;
      // Typing clears the server's red marks; a rule now reads met or not yet.
      li.classList.toggle('met', met);
      li.classList.remove('unmet');
      var state = li.querySelector('.state');
      if (state) state.textContent = met ? ' (done)' : ' (not yet)';
    });
    if (strength) {
      var level = score(pw);
      // A password the policy refuses is never more than weak, however long.
      if (!allMet) level = Math.min(level, 1);
      strength.hidden = false;
      strength.setAttribute('data-level', String(level));
      strength.querySelector('strong').textContent = pw ? LEVELS[level] : 'none yet';
    }
    updateMatch();
  }

  function updateMatch() {
    if (!confirm || !match) return;
    if (!confirm.value) {
      match.hidden = true;
      return;
    }
    var same = confirm.value === password.value;
    match.hidden = false;
    match.classList.toggle('met', same);
    match.textContent = same ? 'Passwords match' : "Passwords don't match yet";
  }

  password.addEventListener('input', update);
  if (confirm) confirm.addEventListener('input', updateMatch);
  if (password.value) update();
  else if (strength) strength.hidden = false;
})();
