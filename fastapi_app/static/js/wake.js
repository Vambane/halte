// Honest wake: hide the "waking up" banner once the server reports the DB is ready.
(function () {
  var wake = document.getElementById('wake-banner');
  if (wake && document.body.getAttribute('data-db-ready') === 'true') {
    wake.hidden = true;
  }
})();
