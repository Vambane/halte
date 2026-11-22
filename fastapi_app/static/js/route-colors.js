// Route colours for the journey schematic.
// The Content-Security-Policy blocks style="" attributes, so templates put a
// route's colour in data-route-color and this sets the --route-color custom
// property through the CSSOM (which the policy allows). Only #hex colours
// are used; anything else keeps the stylesheet's default.
(function () {
  var HEX = /^#[0-9a-fA-F]{3,8}$/;
  document.querySelectorAll('[data-route-color]').forEach(function (el) {
    var colour = el.getAttribute('data-route-color');
    if (HEX.test(colour)) el.style.setProperty('--route-color', colour);
  });
})();
