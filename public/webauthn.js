/*
 * Passkeys (account-plan.md part 5). Without this file, or in a browser without passkeys, every
 * screen still works and the passkey buttons stay hidden. With it:
 *   - a form with data-passkey="get" signs in with a passkey: its data-options URL gives the
 *     options for navigator.credentials.get, and the answer is posted in the form's
 *     `credential` field. With data-autofill, the browser also offers passkeys in the email
 *     field's suggestions (WebAuthn conditional UI);
 *   - a form with data-passkey="create" makes a passkey the same way, with
 *     navigator.credentials.create;
 *   - a button with data-passkey-start="<form id>" starts its form's ceremony.
 * Same-origin requests only (Content-Security-Policy: script-src 'self').
 */
(function () {
  'use strict';

  var supported =
    typeof window.PublicKeyCredential === 'function' &&
    !!navigator.credentials &&
    typeof window.fetch === 'function';

  document.querySelectorAll('form[data-passkey]').forEach(function (form) {
    var kind = form.getAttribute('data-passkey');
    var url = form.getAttribute('data-options');
    var field = form.querySelector('input[name="credential"]');
    var error = document.getElementById(form.id + '-error');
    var buttons = document.querySelectorAll('[data-passkey-start="' + form.id + '"]');
    var autofill = null; // the waiting conditional request, if any

    if (!supported || !url || !field) return;
    document.querySelectorAll('[data-passkey-unsupported]').forEach(function (p) {
      p.hidden = true;
    });
    buttons.forEach(function (b) {
      b.hidden = false;
      b.addEventListener('click', function () {
        run(false);
      });
    });

    if (
      kind === 'get' &&
      form.hasAttribute('data-autofill') &&
      typeof window.PublicKeyCredential.isConditionalMediationAvailable === 'function'
    ) {
      window.PublicKeyCredential.isConditionalMediationAvailable().then(
        function (ok) {
          if (ok) run(true);
        },
        function () {},
      );
    }

    function run(conditional) {
      if (autofill) {
        autofill.abort();
        autofill = null;
      }
      var controller = typeof AbortController === 'function' ? new AbortController() : null;
      if (conditional) autofill = controller;
      say(null);
      busy(!conditional);

      fetch(url, { credentials: 'same-origin', headers: { accept: 'application/json' } })
        .then(function (res) {
          // The sign-in this page belongs to is too old: the page itself asks again.
          if (res.status === 401) {
            location.reload();
            throw { quiet: true };
          }
          if (res.status === 429) throw { name: 'TooOften' };
          if (!res.ok) throw new Error('options');
          return res.json();
        })
        .then(function (options) {
          if (kind === 'create') {
            return navigator.credentials.create({ publicKey: creation(options) });
          }
          var request = { publicKey: requested(options) };
          if (conditional) request.mediation = 'conditional';
          if (controller) request.signal = controller.signal;
          return navigator.credentials.get(request);
        })
        .then(function (credential) {
          if (!credential) throw new Error('none');
          if (conditional) autofill = null;
          field.value = JSON.stringify(serialised(credential));
          if (typeof form.requestSubmit === 'function') form.requestSubmit();
          else form.submit();
        })
        .catch(function (err) {
          busy(false);
          if (conditional || (err && err.quiet)) return;
          var name = err && err.name;
          if (name === 'AbortError') return;
          say(
            name === 'TooOften'
              ? 'Too many tries in a short while. Try again in a few minutes.'
              : name === 'InvalidStateError' && kind === 'create'
                ? 'This device already has a passkey for your account.'
                : name === 'NotAllowedError'
                  ? kind === 'create'
                    ? 'The passkey wasn’t saved. Try again when you’re ready.'
                    : 'The passkey wasn’t used. Try again, or sign in another way.'
                  : 'Passkeys aren’t working here right now. Try again, or sign in another way.',
          );
        });
    }

    function busy(on) {
      buttons.forEach(function (b) {
        if (on) b.setAttribute('aria-busy', 'true');
        else b.removeAttribute('aria-busy');
        b.disabled = on;
      });
    }

    function say(text) {
      if (!error) return;
      var span = error.querySelector('span');
      if (span) span.textContent = text || '';
      error.hidden = !text;
    }
  });

  // ---- JSON <-> the ArrayBuffers WebAuthn takes and gives -----------------------------------

  function bytes(s) {
    var b64 = s.replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4) b64 += '=';
    var bin = atob(b64);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  }

  function text(buffer) {
    var a = new Uint8Array(buffer);
    var bin = '';
    for (var i = 0; i < a.length; i++) bin += String.fromCharCode(a[i]);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function descriptors(list) {
    return (list || []).map(function (c) {
      return { type: 'public-key', id: bytes(c.id), transports: c.transports };
    });
  }

  function requested(o) {
    var r = Object.assign({}, o, { challenge: bytes(o.challenge) });
    if (o.allowCredentials) r.allowCredentials = descriptors(o.allowCredentials);
    return r;
  }

  function creation(o) {
    return Object.assign({}, o, {
      challenge: bytes(o.challenge),
      user: Object.assign({}, o.user, { id: bytes(o.user.id) }),
      excludeCredentials: descriptors(o.excludeCredentials),
    });
  }

  function serialised(c) {
    var r = c.response;
    var out = {
      id: c.id,
      rawId: text(c.rawId),
      type: c.type,
      clientExtensionResults: {},
      response: { clientDataJSON: text(r.clientDataJSON) },
    };
    if (c.authenticatorAttachment) out.authenticatorAttachment = c.authenticatorAttachment;
    if (r.attestationObject) {
      out.response.attestationObject = text(r.attestationObject);
      out.response.transports = typeof r.getTransports === 'function' ? r.getTransports() : [];
    } else {
      out.response.authenticatorData = text(r.authenticatorData);
      out.response.signature = text(r.signature);
      if (r.userHandle) out.response.userHandle = text(r.userHandle);
    }
    return out;
  }
})();
