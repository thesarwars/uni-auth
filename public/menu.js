/*
 * The profile menu in the account centre's top bar is a <details>, so it opens and closes with
 * Enter or Space on its own. This adds what a menu is expected to do besides (WCAG 2.1.1, 2.4.3):
 * Escape closes it and puts focus back on the avatar, and it closes when focus or a click goes
 * elsewhere on the page.
 */
(function () {
  'use strict';

  var menu = document.querySelector('details.me');
  if (!menu) return;
  var summary = menu.querySelector('summary');

  document.addEventListener('keydown', function (e) {
    if (e.key !== 'Escape' || !menu.open) return;
    menu.open = false;
    summary.focus();
  });
  document.addEventListener('click', function (e) {
    if (menu.open && !menu.contains(e.target)) menu.open = false;
  });
  menu.addEventListener('focusout', function (e) {
    if (menu.open && e.relatedTarget && !menu.contains(e.relatedTarget)) menu.open = false;
  });
})();
