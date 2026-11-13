/*
 * Password fields, enhanced (auth-plan.md section 7.4: progressive enhancement). Without this
 * file every screen still works: the rules are listed, and the server checks them on submit.
 * With it:
 *   - every password field gets a show/hide button;
 *   - the rules list marks each rule green when met and red when not, with the same tests the
 *     server applies
 *     (src/credentials/password.service.ts checkPassword);
 *   - "Confirm password" says whether the two match, green or red;
 *   - the code field is shown as one box per digit, and its button waits for every digit;
 *   - a form is sent once: a second click or Enter while the first is on its way does nothing.
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

  // Send each form once. A second copy of the same form (a double click, Enter then a click) used
  // to reach the server after the first had already spent the code, and read as "expired". The
  // server also answers a repeat with where the first went (SignIn.finished); this saves the trip.
  document.querySelectorAll('form').forEach(function (form) {
    form.addEventListener('submit', function (event) {
      if (form.getAttribute('data-sending')) {
        event.preventDefault();
        return;
      }
      form.setAttribute('data-sending', 'true');
      form.setAttribute('aria-busy', 'true');
      // After this event, so the clicked button's name and value are still sent with the form.
      var button = event.submitter;
      if (button) {
        setTimeout(function () {
          button.disabled = true;
          button.setAttribute('data-sent', 'true');
        }, 0);
      }
    });
  });
  // Back to a page the browser kept: its forms can be sent again.
  window.addEventListener('pageshow', function (event) {
    if (!event.persisted) return;
    document.querySelectorAll('form[data-sending]').forEach(function (form) {
      form.removeAttribute('data-sending');
      form.removeAttribute('aria-busy');
    });
    document.querySelectorAll('button[data-sent]').forEach(function (button) {
      button.removeAttribute('data-sent');
      button.disabled = false;
    });
  });

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
    // Its button may sit outside the form, joined to it by form="..." (the screen's actions row).
    var submit =
      code.form &&
      (code.form.querySelector('button[value="verify_code"]') ||
        (code.form.id && document.querySelector('button[form="' + code.form.id + '"]')));
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
  var confirm = document.getElementById('confirm');
  var match = document.getElementById('match');

  function update() {
    var pw = password.value;
    items.forEach(function (li) {
      var test = TESTS[li.getAttribute('data-rule')];
      var met = test ? test(pw, Number(li.getAttribute('data-value'))) : false;
      // Green when met; red once there is something typed that doesn't meet it yet. An empty
      // field shows every rule neutral (this also clears the server's red marks).
      li.classList.toggle('met', met);
      li.classList.toggle('unmet', !met && pw.length > 0);
      var state = li.querySelector('.state');
      if (state) state.textContent = met ? ' (done)' : ' (not yet)';
    });
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
    match.textContent = same ? 'Passwords match' : "Passwords don't match";
  }

  password.addEventListener('input', update);
  if (confirm) confirm.addEventListener('input', updateMatch);
  if (password.value) update();
})();
