/*!
 * nullroute shell engine: a tiny, deterministic Unix-like shell for a browser hacking game.
 * No dependencies, no network. MIT License (c) 2026 Kirtan Bhatt
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.NullrouteShell = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var VERSION = '1.0.0';
  var STORAGE_KEY = 'nullroute.v1';

  // ---------------------------------------------------------------------------
  // Byte / encoding utilities (all game data is ASCII, treated as latin1 bytes)
  // ---------------------------------------------------------------------------

  function toBytes(s) { var b = []; for (var i = 0; i < s.length; i++) b.push(s.charCodeAt(i) & 255); return b; }
  function fromBytes(b) { var s = ''; for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]); return s; }

  var B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

  function b64encode(str, url) {
    var b = toBytes(str), out = '', i;
    for (i = 0; i < b.length; i += 3) {
      var n = (b[i] << 16) | ((b[i + 1] || 0) << 8) | (b[i + 2] || 0);
      out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63] +
        (i + 1 < b.length ? B64[(n >> 6) & 63] : '=') + (i + 2 < b.length ? B64[n & 63] : '=');
    }
    if (url) out = out.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    return out;
  }

  function b64decode(str) {
    var s = String(str).replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
    if (/[^A-Za-z0-9+\/]/.test(s) || s.length % 4 === 1) throw new Error('invalid input');
    var out = [], buf = 0, bits = 0;
    for (var i = 0; i < s.length; i++) {
      buf = (buf << 6) | B64.indexOf(s[i]); bits += 6;
      if (bits >= 8) { bits -= 8; out.push((buf >> bits) & 255); }
    }
    return fromBytes(out);
  }

  function rot13(s) {
    return s.replace(/[a-z]/gi, function (c) {
      var base = c <= 'Z' ? 65 : 97;
      return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
    });
  }

  function hexEncode(s) { return toBytes(s).map(function (x) { return (x < 16 ? '0' : '') + x.toString(16); }).join(''); }
  function hexDecode(h) {
    var c = h.replace(/0x/gi, '').replace(/[\s:]/g, '');
    if (!/^[0-9a-f]*$/i.test(c) || c.length % 2) throw new Error('not hex');
    var out = [];
    for (var i = 0; i < c.length; i += 2) out.push(parseInt(c.substr(i, 2), 16));
    return fromBytes(out);
  }

  // Compact SHA-256 (constants derived from primes at load time).
  var SHA_K = [], SHA_H = [];
  (function () {
    var primes = [], n = 2;
    while (primes.length < 64) { if (primes.every(function (p) { return n % p; })) primes.push(n); n++; }
    var frac = function (x) { return ((x - Math.floor(x)) * 4294967296) | 0; };
    for (var i = 0; i < 64; i++) {
      if (i < 8) SHA_H[i] = frac(Math.pow(primes[i], 1 / 2));
      SHA_K[i] = frac(Math.pow(primes[i], 1 / 3));
    }
  })();

  function sha256(str) {
    var bytes = toBytes(str), len = bytes.length, H = SHA_H.slice(), i, j;
    var rotr = function (x, n) { return (x >>> n) | (x << (32 - n)); };
    bytes.push(0x80);
    while (bytes.length % 64 !== 56) bytes.push(0);
    var hi = Math.floor(len / 0x20000000), lo = (len * 8) >>> 0;
    bytes.push((hi >>> 24) & 255, (hi >>> 16) & 255, (hi >>> 8) & 255, hi & 255,
      (lo >>> 24) & 255, (lo >>> 16) & 255, (lo >>> 8) & 255, lo & 255);
    for (j = 0; j < bytes.length; j += 64) {
      var w = [];
      for (i = 0; i < 16; i++) w[i] = (bytes[j + i * 4] << 24) | (bytes[j + i * 4 + 1] << 16) | (bytes[j + i * 4 + 2] << 8) | bytes[j + i * 4 + 3];
      var a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
      for (i = 0; i < 64; i++) {
        if (i >= 16) {
          var w15 = w[i - 15], w2 = w[i - 2];
          w[i] = (w[i - 16] + (rotr(w15, 7) ^ rotr(w15, 18) ^ (w15 >>> 3)) + w[i - 7] + (rotr(w2, 17) ^ rotr(w2, 19) ^ (w2 >>> 10))) | 0;
        }
        var t1 = (h + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + SHA_K[i] + w[i]) | 0;
        var t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) | 0;
        h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0; H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0;
      H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0; H[6] = (H[6] + g) | 0; H[7] = (H[7] + h) | 0;
    }
    return H.map(function (x) { return ('00000000' + (x >>> 0).toString(16)).slice(-8); }).join('');
  }

  // Deterministic PRNG so generated files are identical on every machine.
  function prng(seed) {
    var s = seed >>> 0;
    return function () { s = (s + 0x6d2b79f5) | 0; var t = Math.imul(s ^ (s >>> 15), 1 | s); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
  }

  function isPrintable(code) { return (code >= 32 && code < 127) || code === 9 || code === 10; }

  var util = { toBytes: toBytes, fromBytes: fromBytes, b64encode: b64encode, b64decode: b64decode, rot13: rot13,
    hexEncode: hexEncode, hexDecode: hexDecode, sha256: sha256, prng: prng };

  // ---------------------------------------------------------------------------
  // Tokenizer: quotes, backslash escapes and pipes
  // ---------------------------------------------------------------------------

  var PIPE = { pipe: true };

  function tokenize(line) {
    var out = [], cur = '', q = null, has = false;
    for (var i = 0; i < line.length; i++) {
      var ch = line[i];
      if (q) {
        if (ch === q) q = null;
        else if (ch === '\\' && q === '"' && (line[i + 1] === '"' || line[i + 1] === '\\')) cur += line[++i];
        else cur += ch;
        continue;
      }
      if (ch === '"' || ch === "'") { q = ch; has = true; continue; }
      if (ch === '\\' && i + 1 < line.length) { cur += line[++i]; has = true; continue; }
      if (/\s/.test(ch)) { if (cur || has) { out.push(cur); cur = ''; has = false; } continue; }
      if (ch === '|') { if (cur || has) { out.push(cur); cur = ''; has = false; } out.push(PIPE); continue; }
      cur += ch;
    }
    if (q) throw new Error('unexpected EOF while looking for matching ' + q);
    if (cur || has) out.push(cur);
    return out;
  }

  // ---------------------------------------------------------------------------
  // Virtual filesystem
  // ---------------------------------------------------------------------------

  function buildFs(files) {
    var root = { dir: true, children: {}, owner: null };
    Object.keys(files).forEach(function (p) {
      var spec = files[p];
      var parts = p.split('/').filter(Boolean), node = root;
      var isDir = p.charAt(p.length - 1) === '/';
      parts.forEach(function (name, idx) {
        var last = idx === parts.length - 1;
        if (last && !isDir) {
          var file = typeof spec === 'string' ? { content: spec } : spec;
          node.children[name] = { dir: false, content: file.content, owner: file.owner || null };
        } else {
          if (!node.children[name]) node.children[name] = { dir: true, children: {}, owner: null };
          node = node.children[name];
          if (last && spec && spec.owner) node.owner = spec.owner;
        }
      });
    });
    return root;
  }

  function normPath(cwd, home, p) {
    if (!p) return cwd;
    if (p === '~') p = home;
    else if (p.indexOf('~/') === 0) p = home + p.slice(1);
    var parts = (p.charAt(0) === '/' ? p : cwd + '/' + p).split('/'), out = [];
    parts.forEach(function (x) { if (!x || x === '.') return; if (x === '..') out.pop(); else out.push(x); });
    return '/' + out.join('/');
  }

  function lookup(fs, abs) {
    var node = fs;
    var parts = abs.split('/').filter(Boolean);
    for (var i = 0; i < parts.length; i++) {
      if (!node.dir || !node.children[parts[i]]) return null;
      node = node.children[parts[i]];
    }
    return node;
  }

  function globToRe(g) {
    return new RegExp('^' + g.replace(/[.+^$()|[\]{}\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$');
  }

  // ---------------------------------------------------------------------------
  // HTTP helpers for simulated web targets
  // ---------------------------------------------------------------------------

  function parseUrl(u) {
    var m = /^(?:(https?):\/\/)?([^\/?#:]+)(?::(\d+))?(\/[^?#]*)?(?:\?([^#]*))?/i.exec(u);
    if (!m) return null;
    var query = {};
    (m[5] || '').split('&').forEach(function (kv) {
      if (!kv) return;
      var i = kv.indexOf('=');
      var k = i === -1 ? kv : kv.slice(0, i), v = i === -1 ? '' : kv.slice(i + 1);
      try { query[decodeURIComponent(k.replace(/\+/g, ' '))] = decodeURIComponent(v.replace(/\+/g, ' ')); }
      catch (e) { query[k] = v; }
    });
    return { scheme: (m[1] || 'http').toLowerCase(), host: m[2].toLowerCase(), path: m[4] || '/', query: query, raw: u };
  }

  // ---------------------------------------------------------------------------
  // Game
  // ---------------------------------------------------------------------------

  var BANNER = [
    "             _  _                  _",
    " _ _   _  _ | || | _ _  ___  _  _ | |_  ___",
    "| ' \\ | || || || || '_|/ _ \\| || ||  _|/ -_)",
    "|_||_| \\_,_||_||_||_|  \\___/ \\_,_| \\__|\\___|"
  ].join('\n');

  function createGame(opts) {
    opts = opts || {};
    var LEVELS = opts.levels || [];
    var storage = opts.storage || null;
    var state = { solved: {}, hints: {}, current: 0 };
    try {
      var saved = storage && JSON.parse(storage.getItem(STORAGE_KEY) || 'null');
      if (saved && typeof saved === 'object') {
        state.solved = saved.solved || {};
        state.hints = saved.hints || {};
        state.current = Math.min(Math.max(0, saved.current | 0), LEVELS.length - 1);
      }
    } catch (e) { /* corrupted or unavailable storage: start fresh */ }

    var level, fs, cwd, user, history = [];

    function save() {
      try { if (storage) storage.setItem(STORAGE_KEY, JSON.stringify(state)); } catch (e) { /* ignore */ }
    }

    function unlocked(i) { return i === 0 || !!state.solved[LEVELS[i - 1].id]; }

    function connect(i) {
      state.current = i;
      level = LEVELS[i];
      fs = buildFs(level.files);
      user = level.user;
      cwd = level.home;
      save();
    }
    connect(state.current);

    function home() { return user === level.user ? level.home : (level.homes && level.homes[user]) || '/root'; }

    function prompt() {
      var p = cwd === home() ? '~' : (cwd.indexOf(home() + '/') === 0 ? '~' + cwd.slice(home().length) : cwd);
      return user + '@' + level.host + ':' + p + (user === 'root' ? '#' : '$');
    }

    function canRead(node) { return !node.owner || node.owner === user || user === 'root'; }

    function resolve(p) { return normPath(cwd, home(), p); }

    function readFile(p) {
      var abs = resolve(p), node = lookup(fs, abs);
      if (!node) throw new Error(p + ': No such file or directory');
      if (node.dir) throw new Error(p + ': Is a directory');
      if (!canRead(node)) throw new Error(p + ': Permission denied');
      return node.content;
    }

    // Split argv into flags and positional args. Short flags may be combined (-la).
    function parseArgs(argv, withValue) {
      withValue = withValue || [];
      var flags = {}, pos = [];
      for (var i = 0; i < argv.length; i++) {
        var a = argv[i];
        if (a === '--') { pos = pos.concat(argv.slice(i + 1)); break; }
        if (/^--[a-z]/.test(a)) {
          var eq = a.indexOf('=');
          if (eq !== -1) flags[a.slice(2, eq)] = a.slice(eq + 1); else flags[a.slice(2)] = true;
        } else if (/^-[a-zA-Z]/.test(a)) {
          for (var j = 1; j < a.length; j++) {
            var f = a[j];
            if (withValue.indexOf(f) !== -1) {
              var rest = a.slice(j + 1);
              flags[f] = rest || argv[++i];
              break;
            }
            flags[f] = true;
          }
        } else pos.push(a);
      }
      return { flags: flags, args: pos };
    }

    function inputOf(args, stdin, cmd) {
      if (args.length) return args.map(readFile).join('');
      if (stdin != null) return stdin;
      throw new Error(cmd + ': missing file operand');
    }

    function lines(s) { var l = s.split('\n'); if (l[l.length - 1] === '') l.pop(); return l; }

    // -------------------------------------------------------------------------
    // Commands. Each returns a string (stdout) or throws Error (stderr).
    // -------------------------------------------------------------------------

    var HELP = {
      help: 'help [command]          show commands, or details for one',
      ls: 'ls [-a] [-l] [path]     list files (-a shows hidden dotfiles)',
      cd: 'cd [dir]                change directory',
      pwd: 'pwd                     print working directory',
      cat: 'cat <file...>           print files',
      head: 'head [-n N] [file]      first N lines',
      tail: 'tail [-n N] [file]      last N lines',
      grep: 'grep [-i -v -n -r -c] <pattern> [file|dir]   search text (regex)',
      find: 'find [path] [-name glob] [-type f|d]          find files',
      wc: 'wc [-l] [file]          count lines, words, bytes',
      sort: 'sort [-r] [file]        sort lines',
      uniq: 'uniq [-c] [file]        collapse repeated lines',
      cut: 'cut -d <delim> -f <n>   pick a field from each line',
      echo: 'echo [-n] <text>        print text (-n: no trailing newline)',
      base64: 'base64 [-d] [file]      encode / decode base64',
      base64url: 'base64url [-d] [file]   base64 with the URL-safe alphabet (used by JWTs)',
      rot13: 'rot13 [file]            rotate letters by 13',
      strings: 'strings [-n N] <file>   printable text inside a binary',
      xxd: 'xxd <file>              hex dump',
      file: 'file <file>             guess a file type',
      xor: 'xor -k <hexkey> [file]  XOR hex input with a single-byte key\n     xor -b [file]           brute-force all 255 keys, show the most readable',
      sha256sum: 'sha256sum [file]        SHA-256 hash',
      crack: 'crack -w <wordlist> <sha256>   dictionary attack against a hash',
      curl: 'curl [-i] [-H "Header: value"] <url>   make an HTTP request',
      git: 'git log | git show <hash> | git status',
      su: 'su <user> <password>    switch user (sandbox takes the password inline)',
      exit: 'exit                    leave a su session',
      whoami: 'whoami / id / hostname / uname -a',
      history: 'history                 commands you have run',
      clear: 'clear                   clear the screen (or Ctrl+L)',
      ssh: 'ssh <host>              connect to a target you have unlocked',
      levels: 'levels                  mission map and progress',
      hint: 'hint                    reveal the next hint for this target',
      submit: 'submit <NR{...}>        submit a captured flag',
      reset: 'reset --yes             wipe all progress'
    };

    var C = {};

    C.help = function (a) {
      if (a.length) {
        var key = a[0] === 'id' || a[0] === 'hostname' || a[0] === 'uname' ? 'whoami' : a[0];
        if (!HELP[key]) throw new Error('help: no help for ' + a[0]);
        return HELP[key] + '\n';
      }
      return 'Goal: find the flag NR{...} on each target, then: submit NR{...}\n\n' +
        Object.keys(HELP).map(function (k) { return '  ' + HELP[k]; }).join('\n') +
        '\n\nPipes work: cat file | base64 -d | rot13\nTab completes, arrow keys walk history.\n';
    };
    C.man = function (a) { return C.help(a); };

    C.ls = function (argv) {
      var p = parseArgs(argv), targets = p.args.length ? p.args : ['.'], out = [];
      targets.forEach(function (t) {
        var abs = resolve(t), node = lookup(fs, abs);
        if (!node) throw new Error('ls: cannot access \'' + t + '\': No such file or directory');
        if (!node.dir) { out.push(t); return; }
        if (!canRead(node)) throw new Error('ls: cannot open directory \'' + t + '\': Permission denied');
        var names = Object.keys(node.children).sort();
        if (!p.flags.a) names = names.filter(function (n) { return n.charAt(0) !== '.'; });
        if (targets.length > 1) out.push(t + ':');
        if (p.flags.l) {
          names.forEach(function (n) {
            var c = node.children[n], own = c.owner || user;
            var size = c.dir ? 4096 : c.content.length;
            out.push((c.dir ? 'drwxr-x---' : '-rw-r-----') + ' 1 ' + pad(own, 6) + ' ' + pad(own, 6) + ' ' +
              padL(String(size), 7) + ' Nov  6 03:14 ' + n + (c.dir ? '/' : ''));
          });
        } else if (names.length) {
          out.push(names.map(function (n) { return n + (node.children[n].dir ? '/' : ''); }).join('  '));
        }
      });
      return out.length ? out.join('\n') + '\n' : '';
    };

    function pad(s, n) { while (s.length < n) s += ' '; return s; }
    function padL(s, n) { while (s.length < n) s = ' ' + s; return s; }

    C.cd = function (a) {
      var abs = resolve(a[0] || home()), node = lookup(fs, abs);
      if (!node) throw new Error('cd: ' + a[0] + ': No such file or directory');
      if (!node.dir) throw new Error('cd: ' + a[0] + ': Not a directory');
      if (!canRead(node)) throw new Error('cd: ' + a[0] + ': Permission denied');
      cwd = abs;
      return '';
    };

    C.pwd = function () { return cwd + '\n'; };

    C.cat = function (a, stdin) { return inputOf(a.filter(function (x) { return x !== '-'; }), stdin, 'cat'); };

    function headTail(fromEnd) {
      return function (argv, stdin) {
        var p = parseArgs(argv, ['n']), n = p.flags.n != null ? parseInt(p.flags.n, 10) : 10;
        if (isNaN(n)) throw new Error('invalid number of lines');
        var l = lines(inputOf(p.args, stdin, fromEnd ? 'tail' : 'head'));
        l = fromEnd ? l.slice(Math.max(0, l.length - n)) : l.slice(0, n);
        return l.length ? l.join('\n') + '\n' : '';
      };
    }
    C.head = headTail(false);
    C.tail = headTail(true);

    C.grep = function (argv, stdin) {
      var p = parseArgs(argv);
      if (!p.args.length) throw new Error('usage: grep [-i -v -n -r -c] <pattern> [file...]');
      var pat = p.args[0], targets = p.args.slice(1), re;
      try { re = new RegExp(pat, p.flags.i ? 'i' : ''); }
      catch (e) { re = new RegExp(pat.replace(/[.*+?^$()|[\]{}\\]/g, '\\$&'), p.flags.i ? 'i' : ''); }
      var sources = [];
      if (p.flags.r || p.flags.R) {
        (targets.length ? targets : ['.']).forEach(function (t) { walk(resolve(t), t === '.' ? '' : t.replace(/\/$/, ''), sources); });
      } else if (targets.length) {
        targets.forEach(function (t) { sources.push({ name: t, text: readFile(t) }); });
      } else if (stdin != null) sources.push({ name: '', text: stdin });
      else throw new Error('grep: no input');
      var multi = sources.length > 1 || p.flags.r || p.flags.R, out = [];
      sources.forEach(function (s) {
        var count = 0;
        lines(s.text).forEach(function (line, idx) {
          if (re.test(line) !== !!p.flags.v) {
            count++;
            if (!p.flags.c) out.push((multi ? s.name + ':' : '') + (p.flags.n ? (idx + 1) + ':' : '') + line);
          }
        });
        if (p.flags.c) out.push((multi ? s.name + ':' : '') + count);
      });
      return out.length ? out.join('\n') + '\n' : '';
    };

    function walk(abs, label, acc) {
      var node = lookup(fs, abs);
      if (!node) throw new Error('grep: ' + (label || abs) + ': No such file or directory');
      if (!node.dir) { if (canRead(node)) acc.push({ name: label || abs, text: node.content }); return; }
      if (!canRead(node)) return;
      Object.keys(node.children).sort().forEach(function (n) { walk(abs.replace(/\/$/, '') + '/' + n, (label ? label + '/' : '') + n, acc); });
    }

    C.find = function (argv) {
      var start = '.', name = null, type = null;
      for (var i = 0; i < argv.length; i++) {
        if (argv[i] === '-name') name = globToRe(argv[++i] || '*');
        else if (argv[i] === '-type') type = argv[++i];
        else if (argv[i] === '-iname') name = new RegExp(globToRe(argv[++i] || '*').source, 'i');
        else start = argv[i];
      }
      var abs = resolve(start), node = lookup(fs, abs), out = [];
      if (!node) throw new Error('find: \'' + start + '\': No such file or directory');
      (function rec(n, label, base) {
        var ok = (!name || name.test(base)) && (!type || (type === 'd') === n.dir);
        if (ok) out.push(label);
        if (n.dir && canRead(n)) Object.keys(n.children).sort().forEach(function (c) { rec(n.children[c], label.replace(/\/$/, '') + '/' + c, c); });
      })(node, start, start.split('/').pop());
      return out.join('\n') + '\n';
    };

    C.wc = function (argv, stdin) {
      var p = parseArgs(argv), t = inputOf(p.args, stdin, 'wc');
      var l = (t.match(/\n/g) || []).length;
      if (p.flags.l) return l + '\n';
      return l + ' ' + (t.trim() ? t.trim().split(/\s+/).length : 0) + ' ' + t.length + '\n';
    };

    C.sort = function (argv, stdin) {
      var p = parseArgs(argv), l = lines(inputOf(p.args, stdin, 'sort')).sort();
      if (p.flags.r) l.reverse();
      return l.length ? l.join('\n') + '\n' : '';
    };

    C.uniq = function (argv, stdin) {
      var p = parseArgs(argv), out = [], prev = null, n = 0;
      lines(inputOf(p.args, stdin, 'uniq')).concat([null]).forEach(function (l) {
        if (l === prev) { n++; return; }
        if (prev !== null) out.push(p.flags.c ? padL(String(n), 7) + ' ' + prev : prev);
        prev = l; n = 1;
      });
      return out.length ? out.join('\n') + '\n' : '';
    };

    C.cut = function (argv, stdin) {
      var p = parseArgs(argv, ['d', 'f']);
      var d = p.flags.d == null ? '\t' : p.flags.d, f = parseInt(p.flags.f, 10);
      if (!f) throw new Error('cut: you must specify a field with -f');
      return lines(inputOf(p.args, stdin, 'cut')).map(function (l) { var parts = l.split(d); return parts[f - 1] != null ? parts[f - 1] : ''; }).join('\n') + '\n';
    };

    C.echo = function (argv) {
      var n = false;
      while (argv[0] === '-n') { n = true; argv = argv.slice(1); }
      return argv.join(' ') + (n ? '' : '\n');
    };

    function b64cmd(url) {
      return function (argv, stdin) {
        var p = parseArgs(argv), t = inputOf(p.args, stdin, url ? 'base64url' : 'base64');
        if (p.flags.d) {
          try { return b64decode(t); } catch (e) { throw new Error((url ? 'base64url' : 'base64') + ': invalid input'); }
        }
        return b64encode(t, url) + '\n';
      };
    }
    C.base64 = b64cmd(false);
    C.base64url = b64cmd(true);

    C.rot13 = function (a, stdin) { return rot13(inputOf(a, stdin, 'rot13')); };

    C.strings = function (argv, stdin) {
      var p = parseArgs(argv, ['n']), min = parseInt(p.flags.n || 4, 10), out = [], cur = '';
      var t = inputOf(p.args, stdin, 'strings');
      for (var i = 0; i <= t.length; i++) {
        var c = i < t.length ? t.charCodeAt(i) : 0;
        if (c >= 32 && c < 127) cur += t[i];
        else { if (cur.length >= min) out.push(cur); cur = ''; }
      }
      return out.length ? out.join('\n') + '\n' : '';
    };

    C.xxd = function (argv, stdin) {
      var b = toBytes(inputOf(argv, stdin, 'xxd')), out = [];
      for (var i = 0; i < b.length; i += 16) {
        var row = b.slice(i, i + 16), hex = '', asc = '';
        row.forEach(function (x, k) { hex += (x < 16 ? '0' : '') + x.toString(16) + (k % 2 ? ' ' : ''); asc += x >= 32 && x < 127 ? String.fromCharCode(x) : '.'; });
        out.push(('0000000' + i.toString(16)).slice(-8) + ': ' + pad(hex, 40) + ' ' + asc);
      }
      return out.join('\n') + '\n';
    };

    C.file = function (a) {
      if (!a.length) throw new Error('file: missing operand');
      return a.map(function (f) {
        var abs = resolve(f), n = lookup(fs, abs);
        if (!n) return f + ': cannot open (No such file or directory)';
        if (n.dir) return f + ': directory';
        if (!canRead(n)) return f + ': regular file, no read permission';
        var t = n.content, bin = toBytes(t.slice(0, 512)).some(function (x) { return !isPrintable(x) && x !== 13; });
        if (bin) return f + ': data';
        if (/^[0-9a-f\s]+$/i.test(t) && t.replace(/\s/g, '').length % 2 === 0) return f + ': ASCII text (looks like hex)';
        if (/^[A-Za-z0-9+\/=\s]+$/.test(t) && t.replace(/\s/g, '').length % 4 === 0 && t.trim().length >= 16) return f + ': ASCII text (looks like base64)';
        if (/^eyJ[\w-]+\.[\w-]+\.?[\w-]*\s*$/.test(t)) return f + ': ASCII text (JSON Web Token)';
        return f + ': ASCII text';
      }).join('\n') + '\n';
    };

    function xorBytes(b, k) { return b.map(function (x) { return x ^ k; }); }

    C.xor = function (argv, stdin) {
      var p = parseArgs(argv, ['k']), raw = inputOf(p.args, stdin, 'xor'), data;
      try { data = toBytes(hexDecode(raw)); } catch (e) { data = toBytes(raw); }
      if (p.flags.b) {
        var cands = [];
        for (var k = 1; k < 256; k++) {
          var x = xorBytes(data, k);
          if (!x.every(isPrintable)) continue;
          var score = x.filter(function (c) { return (c >= 97 && c <= 122) || c === 32; }).length / x.length;
          cands.push({ k: k, s: score, t: fromBytes(x) });
        }
        if (!cands.length) return 'no single-byte key produces readable text\n';
        cands.sort(function (a, b) { return b.s - a.s; });
        return cands.slice(0, 5).map(function (c) { return 'key 0x' + ('0' + c.k.toString(16)).slice(-2) + '  ' + c.t.replace(/\n/g, ' '); }).join('\n') + '\n';
      }
      if (p.flags.k == null) throw new Error('usage: xor -k <hexkey> [file]   or   xor -b [file]');
      var key = parseInt(String(p.flags.k).replace(/^0x/i, ''), 16);
      if (isNaN(key) || key < 0 || key > 255) throw new Error('xor: key must be one byte, e.g. -k 4e');
      return fromBytes(xorBytes(data, key)) + '\n';
    };

    C.sha256sum = function (a, stdin) {
      if (a.length) return a.map(function (f) { return sha256(readFile(f)) + '  ' + f; }).join('\n') + '\n';
      if (stdin == null) throw new Error('sha256sum: missing input');
      return sha256(stdin) + '  -\n';
    };

    C.crack = function (argv) {
      var p = parseArgs(argv, ['w']);
      var hash = (p.args[0] || '').toLowerCase().replace(/^.*\$/, '');
      if (!p.flags.w || !/^[0-9a-f]{64}$/.test(hash)) throw new Error('usage: crack -w <wordlist> <sha256-hash>');
      var words = lines(readFile(p.flags.w));
      for (var i = 0; i < words.length; i++) {
        if (sha256(words[i]) === hash) return '[*] loaded ' + words.length + ' candidates\n[+] cracked after ' + (i + 1) + ' tries: ' + words[i] + '\n';
      }
      return '[*] loaded ' + words.length + ' candidates\n[-] exhausted wordlist, no match\n';
    };

    C.curl = function (argv) {
      var headers = {}, method = 'GET', include = false, url = null;
      for (var i = 0; i < argv.length; i++) {
        var a = argv[i];
        if (a === '-H' || a === '--header') {
          var h = argv[++i] || '', c = h.indexOf(':');
          if (c > 0) headers[h.slice(0, c).trim().toLowerCase()] = h.slice(c + 1).trim();
        } else if (a === '-X' || a === '--request') method = (argv[++i] || 'GET').toUpperCase();
        else if (a === '-i' || a === '--include') include = true;
        else if (a === '-s' || a === '-k' || a === '-L' || a === '-v') { /* accepted, no effect */ }
        else if (a.charAt(0) === '-') throw new Error('curl: option ' + a + ' is not supported in this sandbox');
        else url = a;
      }
      if (!url) throw new Error('curl: no URL specified (try: curl http://host/)');
      var req = parseUrl(url);
      var site = req && level.http && level.http[req.host];
      if (!site) throw new Error('curl: (6) Could not resolve host: ' + (req ? req.host : url));
      req.method = method; req.headers = headers;
      var res = site(req) || { status: 404, body: 'Not Found\n' };
      var body = res.body || '';
      if (body && body.charAt(body.length - 1) !== '\n') body += '\n';
      if (!include) return body;
      var head = 'HTTP/1.1 ' + res.status + ' ' + ({ 200: 'OK', 400: 'Bad Request', 401: 'Unauthorized', 403: 'Forbidden', 404: 'Not Found', 500: 'Internal Server Error' }[res.status] || '') + '\n';
      Object.keys(res.headers || {}).forEach(function (k) { head += k + ': ' + res.headers[k] + '\n'; });
      return head + '\n' + body;
    };

    C.git = function (argv) {
      var g = level.git;
      if (!g || (cwd + '/').indexOf(g.root + '/') !== 0) throw new Error('fatal: not a git repository (or any of the parent directories): .git');
      var sub = argv[0];
      if (sub === 'log') {
        var one = argv.indexOf('--oneline') !== -1;
        return g.commits.slice().reverse().map(function (c) {
          return one ? c.hash.slice(0, 7) + ' ' + c.msg : 'commit ' + c.hash + '\nAuthor: ' + c.author + '\nDate:   ' + c.date + '\n\n    ' + c.msg + '\n';
        }).join(one ? '\n' : '\n') + '\n';
      }
      if (sub === 'show') {
        var ref = argv[1] || g.commits[g.commits.length - 1].hash;
        if (ref === 'HEAD') ref = g.commits[g.commits.length - 1].hash;
        var hit = ref.length >= 4 && g.commits.filter(function (c) { return c.hash.indexOf(ref) === 0; })[0];
        if (!hit) throw new Error('fatal: bad revision \'' + ref + '\'');
        return 'commit ' + hit.hash + '\nAuthor: ' + hit.author + '\nDate:   ' + hit.date + '\n\n    ' + hit.msg + '\n\n' + hit.diff + '\n';
      }
      if (sub === 'status') return 'On branch main\nnothing to commit, working tree clean\n';
      if (sub === 'branch') return '* main\n';
      if (!sub) return 'usage: git log [--oneline] | git show <hash> | git status\n';
      throw new Error('git: \'' + sub + '\' is not available in this sandbox');
    };

    C.su = function (a) {
      var who = a[0] || 'root', pw = a[1];
      var users = level.users || {};
      if (!(who in users)) throw new Error('su: user ' + who + ' does not exist or cannot log in here');
      if (pw == null) throw new Error('su: in this sandbox, give the password inline: su ' + who + ' <password>');
      if (users[who] !== pw) throw new Error('su: Authentication failure');
      user = who; cwd = home();
      return { text: 'Authenticated. You are now ' + who + '.\n', cls: 'ok' };
    };

    C.exit = function () {
      if (user !== level.user) { user = level.user; cwd = home(); return 'logout\n'; }
      return 'Connection to ' + level.host + ' stays open. Use "ssh <host>" to move between targets.\n';
    };
    C.logout = C.exit;

    C.whoami = function () { return user + '\n'; };
    C.id = function () { var uid = user === 'root' ? 0 : (user === level.user ? 1000 : 1001); return 'uid=' + uid + '(' + user + ') gid=' + uid + '(' + user + ') groups=' + uid + '(' + user + ')\n'; };
    C.hostname = function () { return level.host + '\n'; };
    C.uname = function (a) { return a[0] === '-a' ? 'Linux ' + level.host + ' 6.8.0-nullroute #1 SMP PREEMPT_DYNAMIC x86_64 GNU/Linux\n' : 'Linux\n'; };
    C.date = function () { return 'Fri Nov  6 03:14:07 UTC 2026\n'; };
    C.history = function () { return history.map(function (h, i) { return padL(String(i + 1), 5) + '  ' + h; }).join('\n') + '\n'; };
    C.sudo = function () { throw new Error(user + ' is not in the sudoers file. This incident will be reported.'); };
    C.rm = function (a) { if (a.join(' ').indexOf('-rf /') !== -1 || a.join(' ').indexOf('-rf ~') !== -1) return { text: 'Nice try. The filesystem is read-only, and so is your karma.\n', cls: 'dim' }; throw new Error('rm: read-only file system'); };
    C.touch = C.mkdir = C.mv = C.cp = C.nano = C.vim = C.vi = function () { throw new Error('read-only file system: you are a guest here'); };
    C.ping = C.nmap = C.wget = C.nc = function () { throw new Error('outbound connections are blocked. Use curl against the hosts this target can see.'); };

    C.ssh = function (a) {
      var target = (a[0] || '').replace(/^.*@/, '').toLowerCase();
      if (!target) throw new Error('usage: ssh <host>   (see: levels)');
      var idx = -1;
      LEVELS.forEach(function (l, i) { if (l.host === target || String(i + 1) === target) idx = i; });
      if (idx === -1) throw new Error('ssh: Could not resolve hostname ' + target);
      if (!unlocked(idx)) throw new Error('ssh: connect to host ' + target + ' port 22: Connection refused (root ' + LEVELS[idx - 1].host + ' first)');
      connect(idx);
      return { text: motd(), cls: 'motd' };
    };

    function motd() {
      var l = level, n = state.current + 1;
      return '\nConnected to ' + l.host + '  [target ' + n + '/' + LEVELS.length + ']' +
        (state.solved[l.id] ? '  (already rooted)' : '') + '\n' +
        '── ' + l.title + ' ──\n' + l.brief + '\n';
    }

    C.levels = function () {
      var out = LEVELS.map(function (l, i) {
        var mark = state.solved[l.id] ? '[✓]' : (unlocked(i) ? '[ ]' : '[■]');
        var name = unlocked(i) ? l.title : '???';
        return ' ' + mark + ' ' + padL(String(i + 1), 2) + '  ' + pad(l.host, 10) + ' ' + name + (i === state.current ? '   <- you are here' : '');
      });
      var done = Object.keys(state.solved).length;
      return { text: out.join('\n') + '\n\n ' + done + '/' + LEVELS.length + ' targets rooted.  [✓] rooted  [ ] open  [■] locked\n', cls: 'acc' };
    };

    C.hint = function () {
      var used = state.hints[level.id] || 0, hs = level.hints || [];
      if (used >= hs.length) return { text: 'No more hints for this target. You have got this.\n', cls: 'dim' };
      state.hints[level.id] = used + 1;
      save();
      return { text: 'hint ' + (used + 1) + '/' + hs.length + ': ' + hs[used] + '\n', cls: 'acc' };
    };

    C.submit = function (a) {
      var flag = (a.join(' ') || '').trim();
      if (!flag) throw new Error('usage: submit NR{...}');
      if (flag !== level.flag) {
        var other = LEVELS.filter(function (l) { return l.flag === flag; })[0];
        if (other) throw new Error('That flag belongs to ' + other.host + '. You are on ' + level.host + '.');
        throw new Error('Incorrect flag. Flags look like NR{...} and are case-sensitive.');
      }
      if (state.solved[level.id]) return { text: 'Already captured. ' + nextStep() + '\n', cls: 'ok' };
      state.solved[level.id] = true;
      save();
      var all = Object.keys(state.solved).length === LEVELS.length;
      var msg = '\n  ✓ FLAG ACCEPTED: ' + level.host + ' rooted.\n  ' + (level.lesson ? 'Lesson: ' + level.lesson + '\n  ' : '') + nextStep() + '\n';
      if (all) {
        msg += '\n  ★ ALL ' + LEVELS.length + ' TARGETS ROOTED ★\n  You walked through hidden files, log forensics, encodings, firmware, git history,\n  recon, JWT forgery, SQL injection, password cracking and XOR crypto.\n  The Halcyon contract is complete. Welcome to nullroute.\n';
      }
      return { text: msg, cls: 'flag' };
    };

    function nextStep() {
      for (var i = 0; i < LEVELS.length; i++) if (!state.solved[LEVELS[i].id]) return 'Next target unlocked: ssh ' + LEVELS[i].host;
      return 'Every target is rooted.';
    }

    C.reset = function (a) {
      if (a[0] !== '--yes') throw new Error('This wipes all progress. Run: reset --yes');
      state = { solved: {}, hints: {}, current: 0 };
      connect(0);
      return { text: 'Progress wiped.\n' + motd(), cls: 'dim' };
    };

    C.banner = function () { return { text: BANNER + '\n', cls: 'acc' }; };

    // -------------------------------------------------------------------------
    // Execution
    // -------------------------------------------------------------------------

    function exec(line) {
      line = String(line == null ? '' : line);
      if (!line.trim()) return { lines: [] };
      history.push(line);
      if (history.length > 500) history.shift();
      var tokens;
      try { tokens = tokenize(line); } catch (e) { return { lines: [{ text: 'nullroute: ' + e.message, cls: 'err' }] }; }
      if (tokens[0] === 'clear' && tokens.length === 1) return { clear: true, lines: [] };
      var stages = [[]];
      tokens.forEach(function (t) { if (t === PIPE) stages.push([]); else stages[stages.length - 1].push(t); });
      if (stages.some(function (s) { return !s.length; })) return { lines: [{ text: 'nullroute: syntax error near unexpected token \'|\'', cls: 'err' }] };

      var stdin = null, out = [], cls = null;
      for (var i = 0; i < stages.length; i++) {
        var name = stages[i][0], fn = Object.prototype.hasOwnProperty.call(C, name) ? C[name] : null;
        if (!fn) { out.push({ text: name + ': command not found. Type help.', cls: 'err' }); return { lines: out }; }
        try {
          var r = fn(stages[i].slice(1), stdin);
          if (r && typeof r === 'object') { cls = r.cls; r = r.text; } else cls = null;
          stdin = r == null ? '' : String(r);
        } catch (e) {
          out.push({ text: e.message, cls: 'err' });
          return { lines: out };
        }
      }
      if (stdin) {
        var l = stdin.split('\n');
        if (l[l.length - 1] === '') l.pop();
        l.forEach(function (t) { out.push({ text: t, cls: cls }); });
      }
      return { lines: out };
    }

    function complete(line) {
      var tokens = line.split(/\s+/), last = tokens[tokens.length - 1], opts;
      if (tokens.length === 1) {
        opts = Object.keys(C).filter(function (c) { return c.indexOf(last) === 0; });
      } else if (tokens[0] === 'ssh') {
        opts = LEVELS.filter(function (l, i) { return unlocked(i) && l.host.indexOf(last) === 0; }).map(function (l) { return l.host; });
      } else {
        var slash = last.lastIndexOf('/'), dirPart = slash === -1 ? '' : last.slice(0, slash + 1), base = last.slice(slash + 1);
        var node = lookup(fs, resolve(dirPart || '.'));
        opts = node && node.dir ? Object.keys(node.children).filter(function (n) { return n.indexOf(base) === 0 && (base.charAt(0) === '.' || n.charAt(0) !== '.'); })
          .map(function (n) { return dirPart + n + (node.children[n].dir ? '/' : ''); }) : [];
      }
      opts.sort();
      if (!opts.length) return { line: line, options: [] };
      var common = opts.reduce(function (a, b) { var i = 0; while (i < a.length && a[i] === b[i]) i++; return a.slice(0, i); });
      var done = opts.length === 1 && common.charAt(common.length - 1) !== '/' ? ' ' : '';
      tokens[tokens.length - 1] = common + done;
      return { line: tokens.join(' '), options: opts.length > 1 ? opts : [] };
    }

    function welcome() {
      var done = Object.keys(state.solved).length;
      return [{ text: BANNER, cls: 'acc' },
        { text: '', cls: null },
        { text: 'nullroute v' + VERSION + ' · a hacking game that runs entirely in your browser', cls: 'dim' },
        { text: 'You are a contractor hired to red-team Halcyon Dynamics. Ten machines. Ten flags.', cls: null },
        { text: 'Type help to see commands, hint if you are stuck, levels for the mission map.', cls: null },
        { text: done ? 'Progress restored: ' + done + '/' + LEVELS.length + ' targets rooted.' : 'Start by looking around: ls', cls: 'dim' }]
        .concat(motd().split('\n').filter(function (x, i, a) { return i < a.length - 1; }).map(function (t) { return { text: t, cls: 'motd' }; }));
    }

    return {
      exec: exec,
      complete: complete,
      prompt: prompt,
      welcome: welcome,
      progress: function () { return { solved: Object.keys(state.solved).length, total: LEVELS.length, current: state.current, host: level.host, title: level.title }; },
      _state: function () { return { cwd: cwd, user: user, level: level.id }; }
    };
  }

  return { VERSION: VERSION, createGame: createGame, tokenize: tokenize, util: util };
});
