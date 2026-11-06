/* nullroute terminal UI */
(function () {
  'use strict';

  var storage = null;
  try { storage = window.localStorage; storage.getItem('x'); } catch (e) { storage = null; }

  var game = window.NullrouteShell.createGame({ levels: window.NullrouteLevels(window.NullrouteShell.util), storage: storage });

  var $ = function (id) { return document.getElementById(id); };
  var term = $('term'), out = $('out'), cmd = $('cmd'), promptEl = $('prompt');
  var hist = [], hpos = 0, draft = '', busy = false;
  var MAX_NODES = 4000;
  var reduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  function line(text, cls) {
    var d = document.createElement('div');
    if (cls) d.className = cls;
    d.textContent = text;
    out.appendChild(d);
    return d;
  }

  function echoCommand(p, c) {
    var d = document.createElement('div');
    d.className = 'cmdline';
    var s = document.createElement('span');
    s.className = 'p';
    s.textContent = p + ' ';
    d.appendChild(s);
    d.appendChild(document.createTextNode(c));
    out.appendChild(d);
  }

  function trim() {
    while (out.childNodes.length > MAX_NODES) out.removeChild(out.firstChild);
  }

  function scroll() { term.scrollTop = term.scrollHeight; }

  function refresh() {
    var p = game.progress();
    promptEl.textContent = game.prompt();
    $('title').textContent = game.prompt().replace(/[$#]$/, '') + '  —  ' + p.title;
    document.title = p.solved === p.total ? 'nullroute · all targets rooted' : 'nullroute · ' + p.host + ' (' + p.solved + '/' + p.total + ')';
    var pips = $('pips');
    pips.textContent = '';
    for (var i = 0; i < p.total; i++) {
      var b = document.createElement('b');
      if (i < p.solved) b.className = 'done';
      if (i === p.current) b.className += ' here';
      b.title = 'target ' + (i + 1);
      pips.appendChild(b);
    }
    pips.setAttribute('aria-label', p.solved + ' of ' + p.total + ' targets rooted');
  }

  function run(text) {
    echoCommand(game.prompt(), text);
    if (text.trim()) { hist.push(text); if (hist.length > 200) hist.shift(); }
    hpos = hist.length;
    var res = game.exec(text);
    if (res.clear) { out.textContent = ''; }
    var lines = res.lines;
    var limit = 3000;
    lines.slice(0, limit).forEach(function (l) { line(l.text, l.cls); });
    if (lines.length > limit) line('... ' + (lines.length - limit) + ' more lines (tip: pipe into grep, head or tail)', 'dim');
    if (lines.some(function (l) { return l.cls === 'flag' && /FLAG ACCEPTED/.test(l.text); })) {
      document.body.classList.add('pwned');
      setTimeout(function () { document.body.classList.remove('pwned'); }, 1400);
    }
    trim();
    refresh();
    scroll();
  }

  $('form').addEventListener('submit', function (e) {
    e.preventDefault();
    if (busy) return;
    var v = cmd.value;
    cmd.value = '';
    run(v);
  });

  function complete() {
    var r = game.complete(cmd.value);
    if (r.options.length) {
      echoCommand(game.prompt(), cmd.value);
      line(r.options.join('   '), 'opts');
      scroll();
    }
    cmd.value = r.line;
  }

  function historyStep(dir) {
    if (!hist.length) return;
    if (hpos === hist.length) draft = cmd.value;
    hpos = Math.max(0, Math.min(hist.length, hpos + dir));
    cmd.value = hpos === hist.length ? draft : hist[hpos];
    setTimeout(function () { cmd.setSelectionRange(cmd.value.length, cmd.value.length); }, 0);
  }

  cmd.addEventListener('keydown', function (e) {
    if (e.key === 'Tab') { e.preventDefault(); complete(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); historyStep(-1); }
    else if (e.key === 'ArrowDown') { e.preventDefault(); historyStep(1); }
    else if (e.ctrlKey && (e.key === 'l' || e.key === 'L')) { e.preventDefault(); out.textContent = ''; }
    else if (e.ctrlKey && (e.key === 'c' || e.key === 'C') && !window.getSelection().toString()) {
      e.preventDefault(); echoCommand(game.prompt(), cmd.value + '^C'); cmd.value = ''; scroll();
    }
  });

  term.addEventListener('click', function () {
    if (!window.getSelection().toString()) cmd.focus({ preventScroll: true });
  });

  document.querySelectorAll('.keys button').forEach(function (b) {
    b.addEventListener('mousedown', function (e) { e.preventDefault(); });
    b.addEventListener('click', function () {
      var c = b.getAttribute('data-cmd'), k = b.getAttribute('data-key');
      if (c) run(c);
      else if (k === 'tab') complete();
      else if (k === 'up') historyStep(-1);
      else if (k === 'pipe') cmd.value += (cmd.value && !/\s$/.test(cmd.value) ? ' ' : '') + '| ';
      cmd.focus();
    });
  });

  $('ver').textContent = 'v' + window.NullrouteShell.VERSION;

  // Boot sequence
  var welcome = game.welcome();
  refresh();
  if (reduced) {
    welcome.forEach(function (l) { line(l.text, l.cls); });
    cmd.focus();
  } else {
    busy = true;
    var i = 0;
    (function next() {
      if (i >= welcome.length) { busy = false; cmd.focus(); scroll(); return; }
      line(welcome[i].text, welcome[i].cls);
      i++;
      scroll();
      setTimeout(next, i < 5 ? 70 : 45);
    })();
  }

  if ('serviceWorker' in navigator && location.protocol === 'https:') {
    window.addEventListener('load', function () { navigator.serviceWorker.register('sw.js').catch(function () {}); });
  }
})();
