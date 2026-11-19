/*
 * Profile photo, enhanced: the chosen file is shown in the avatar before it is saved, cropped as
 * it will be (a centred square in a circle). Without this file the page still works; the server
 * makes the photo either way (src/photos/photos.ts). A data: URL, as the policy allows images
 * from 'self', https: and data: only.
 */
(function () {
  'use strict';

  var input = document.getElementById('photo');
  var preview = document.getElementById('photo-preview');
  if (!input || !preview || !window.FileReader) return;

  input.addEventListener('change', function () {
    var file = input.files && input.files[0];
    if (!file || !/^image\/(jpeg|png|webp)$/.test(file.type)) return;
    var reader = new FileReader();
    reader.onload = function () {
      var img = document.createElement('img');
      img.alt = '';
      img.src = String(reader.result);
      preview.textContent = '';
      preview.appendChild(img);
      preview.classList.add('has-photo');
    };
    reader.readAsDataURL(file);
  });
})();
