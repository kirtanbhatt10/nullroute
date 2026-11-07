/*!
 * nullroute levels: twelve targets at the fictional Halcyon Dynamics.
 * Yes, the flags are in this file. Reading the source is a legitimate hacking technique.
 * The fun is in breaking in the intended way. MIT License (c) 2026 Kirtan Bhatt
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory;
  else root.NullrouteLevels = factory;
})(typeof self !== 'undefined' ? self : this, function (util) {
  'use strict';

  var rand = util.prng(1337);
  var pick = function (arr) { return arr[Math.floor(rand() * arr.length)]; };
  var two = function (n) { return (n < 10 ? '0' : '') + n; };
  var ip = function () { return pick(['185.220.101', '45.155.205', '103.152.18', '194.26.29', '91.240.118']) + '.' + Math.floor(rand() * 254 + 1); };

  // ---------------------------------------------------------------- level 2
  function authLog(flag) {
    var out = [], users = ['root', 'admin', 'oracle', 'ubuntu', 'test', 'git', 'postgres', 'deploy'];
    for (var i = 0; i < 2400; i++) {
      var t = 'Nov  6 ' + two(Math.floor(i / 100)) + ':' + two(Math.floor(rand() * 60)) + ':' + two(Math.floor(rand() * 60)) + ' needle ';
      var r = rand();
      if (i === 1717) out.push(t + 'backup-agent[811]: uploaded archive, session token=' + flag);
      else if (i === 640) out.push(t + 'ctf-decoy[66]: flag{nope_wrong_format_keep_looking}');
      else if (r < 0.62) out.push(t + 'sshd[' + Math.floor(rand() * 9000 + 1000) + ']: Failed password for invalid user ' + pick(users) + ' from ' + ip() + ' port ' + Math.floor(rand() * 60000 + 1024) + ' ssh2');
      else if (r < 0.8) out.push(t + 'sshd[' + Math.floor(rand() * 9000 + 1000) + ']: Connection closed by authenticating user root ' + ip() + ' port ' + Math.floor(rand() * 60000 + 1024) + ' [preauth]');
      else if (r < 0.92) out.push(t + 'CRON[' + Math.floor(rand() * 9000 + 1000) + ']: pam_unix(cron:session): session opened for user root(uid=0)');
      else out.push(t + 'systemd[1]: Started Session ' + Math.floor(rand() * 900 + 100) + ' of User ops.');
    }
    return out.join('\n') + '\n';
  }

  // ---------------------------------------------------------------- level 4
  function firmware(secret) {
    var junk = function (n) { var s = ''; for (var i = 0; i < n; i++) { var c = Math.floor(rand() * 256); s += String.fromCharCode(c >= 32 && c < 127 ? (c + 128) & 255 : c); } return s; };
    var parts = ['\x7fELF\x02\x01\x01', 'U-Boot 2019.07 (Halcyon build 0x3f)', 'halcyon-fw v3.2.1-rc4', '/etc/init.d/rcS',
      'console=ttyS0,115200', util.rot13(secret), 'ERROR: watchdog timeout', 'Copyright (C) Halcyon Dynamics', '/dev/mtdblock3'];
    return parts.map(function (p) { return junk(60 + Math.floor(rand() * 80)) + p; }).join('') + junk(120);
  }

  // ---------------------------------------------------------------- level 7
  var ORIGINAL_JWT = util.b64encode('{"alg":"HS256","typ":"JWT"}', true) + '.' +
    util.b64encode('{"sub":"guest","role":"user","iat":1793952000}', true) + '.' +
    'm9QkVx3l8wE7Rr2bYtZ1pA6sN4dHcKfU0jLgTqWvXoI';

  function parseJwt(tok) {
    var parts = String(tok).split('.');
    if (parts.length < 2 || parts.length > 3) return null;
    try { return { header: JSON.parse(util.b64decode(parts[0])), payload: JSON.parse(util.b64decode(parts[1])), sig: parts[2] || '' }; }
    catch (e) { return null; }
  }

  function apiSite(flag) {
    return function (req) {
      var json = function (status, obj) { return { status: status, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(obj, null, 2) }; };
      if (req.path === '/' || req.path === '') {
        return json(200, { service: 'halcyon-api', version: '2.4.1', endpoints: ['GET /whoami', 'GET /admin'], auth: 'Authorization: Bearer <jwt>' });
      }
      if (req.path !== '/whoami' && req.path !== '/admin') return json(404, { error: 'no such endpoint' });
      var auth = req.headers.authorization || '';
      var tok = auth.replace(/^Bearer\s+/i, '').trim();
      if (!tok) return json(401, { error: 'missing Authorization: Bearer <token> header' });
      var t = parseJwt(tok);
      if (!t || !t.header || !t.payload) return json(400, { error: 'malformed token: expected base64url(header).base64url(payload).signature' });
      var alg = String(t.header.alg || '');
      if (alg.toLowerCase() === 'none') {
        // The bug: the library trusts the token's own claim that it needs no signature.
      } else if (alg === 'HS256') {
        if (tok !== ORIGINAL_JWT) return json(401, { error: 'invalid signature' });
      } else return json(400, { error: 'unsupported alg ' + alg });
      if (req.path === '/whoami') return json(200, { sub: t.payload.sub, role: t.payload.role, verified_with: alg });
      if (t.payload.role !== 'admin') return json(403, { error: 'admins only', you: { sub: t.payload.sub, role: t.payload.role } });
      return json(200, { message: 'welcome, administrator', flag: flag });
    };
  }

  // ---------------------------------------------------------------- level 8
  function shopSite(flag) {
    return function (req) {
      if (req.path === '/' || req.path === '') {
        return { status: 200, headers: { 'Content-Type': 'text/html' }, body: '<!doctype html>\n<h1>Halcyon Staff Shop</h1>\n<form action="/login" method="get">\n  <input name="user"> <input name="pass" type="password">\n  <button>Log in</button>\n</form>\n<!-- TODO(ravi): remove debug=1 output before launch -->\n' };
      }
      if (req.path !== '/login') return { status: 404, body: 'Not Found' };
      var u = req.query.user, p = req.query.pass;
      if (u == null || p == null) return { status: 400, body: 'usage: /login?user=<name>&pass=<password>' };
      var sql = "SELECT * FROM staff WHERE username='" + u + "' AND password='" + p + "'";
      var debug = req.query.debug === '1' ? '\n[debug] ' + sql : '';
      // Strip an SQL comment that is outside a string literal, the way MySQL would.
      var effective = '', inStr = false;
      for (var i = 0; i < sql.length; i++) {
        var ch = sql[i];
        if (ch === "'") inStr = !inStr;
        if (!inStr && (sql.substr(i, 2) === '--' || ch === '#')) break;
        effective += ch;
      }
      if (((effective.match(/'/g) || []).length % 2) !== 0) {
        return { status: 500, body: 'SQL error: You have an error in your SQL syntax near \'' + sql.slice(sql.indexOf(u), sql.indexOf(u) + 40) + '\'' + debug };
      }
      var tautology = /'\s*or\s*('?)([\w ]*)\1\s*=\s*\1\2\1/i.test(effective) || /\bor\s+1\s*=\s*1\b/i.test(effective) || /\bor\s+true\b/i.test(effective);
      var userOnly = /username='admin'\s*$/i.test(effective.trim());
      if (tautology || userOnly) {
        return { status: 200, body: 'Welcome back, admin.\nStaff discount code: ' + flag + debug };
      }
      return { status: 401, body: 'Login failed: invalid username or password.' + debug };
    };
  }

  // ---------------------------------------------------------------- level 9
  var WORDS = ('123456 password 12345678 qwerty 123456789 12345 1234 111111 1234567 dragon 123123 baseball abc123 football monkey ' +
    'letmein 696969 shadow master 666666 qwertyuiop 123321 mustang 1234567890 michael 654321 superman 1qaz2wsx 7777777 ' +
    '121212 000000 qazwsx 123qwe killer trustno1 jordan jennifer zxcvbnm asdfgh hunter buster soccer harley ' +
    'batman andrew tigger sunshine iloveyou 2000 charlie robert thomas hockey ranger daniel starwars klaster 112233 ' +
    'george computer michelle jessica pepper 1111 zxcvbn 555555 11111111 131313 freedom 777777 pass maggie 159753 ' +
    'aaaaaa ginger princess joshua cheese amanda summer love ashley nicole chelsea biteme matthew access yankees ' +
    '987654321 dallas austin thunder taylor matrix mobilemail mom monitor monitoring montana moon moscow halcyon ' +
    'halcyon123 Halcyon2026 welcome welcome1 admin admin123 changeme P@ssw0rd Summer2026 Winter2025 india123 ' +
    'mumbai bangalore cricket sachin10 virat18 dhoni07 password1 qwerty123 iloveyou2 nightingale nightingale7 ' +
    'falcon falcon99 phoenix orion orion42 sentinel vault vault2026 keyboard coffee').split(' ');
  var VAULT_PASSWORD = 'nightingale7';

  // --------------------------------------------------------------- level 10
  var TRANSMISSION = 'TRANSMISSION 7/7 :: courier confirmed. Vault override phrase follows :: ';

  // ------------------------------------------------------------------ flags
  var F = [
    'NR{h1dd3n_1n_pl41n_s1ght}',
    'NR{gr3p_th3_h4yst4ck}',
    'NR{b4s3_64_1s_n0t_3ncrypt10n}',
    'NR{str1ngs_th3n_r0t4t3}',
    'NR{g1t_n3v3r_f0rg3ts}',
    'NR{r0b0ts_txt_1s_n0t_4cc3ss_c0ntr0l}',
    'NR{4lg_n0n3_m34ns_n0_s3cur1ty}',
    'NR{s4n1t1z3_y0ur_1nputs}',
    'NR{w34k_p4ssw0rds_f4ll_f4st}',
    'NR{x0r_1s_0nly_4s_str0ng_4s_1ts_k3y}',
    'NR{1d0r_ch3ck_wh0_0wns_1t}',
    'NR{d0t_d0t_sl4sh_3sc4p3s_r00t}'
  ];

  var hex = util.hexEncode(util.fromBytes(util.toBytes(TRANSMISSION + F[9] + ' :: end').map(function (b) { return b ^ 0x5a; })))
    .match(/.{1,32}/g).map(function (row) { return row.match(/.{2}/g).join(' '); }).join('\n') + '\n';

  return [
    {
      id: 'gate', host: 'gate', user: 'guest', home: '/home/guest',
      title: 'Hidden in plain sight',
      brief: 'Your first foothold: a forgotten jump box. Someone left something behind in the home folder.\nTry: ls',
      flag: F[0],
      lesson: 'Files starting with a dot are hidden by default. ls -a shows them. Attackers always look.',
      hints: ['ls only shows "normal" files. Run help ls.', 'Dotfiles (names starting with .) are hidden. Try ls -a', 'cat .flag then submit what you find.'],
      files: {
        '/home/guest/README.txt': 'Welcome to Halcyon Dynamics jump box "gate".\n\nThis machine is scheduled for decommissioning.\nPersonal files have been "removed".\n\n  - IT Ops\n',
        '/home/guest/notes.txt': 'todo:\n- rotate keys\n- clean up home dir before audit\n- stop leaving things in dotfiles (lol)\n',
        '/home/guest/.flag': F[0] + '\n',
        '/home/guest/.bash_history': 'ls\nvim .flag\nchmod 600 .flag\nexit\n',
        '/home/guest/projects/': {},
        '/etc/hostname': 'gate\n'
      }
    },
    {
      id: 'needle', host: 'needle', user: 'guest', home: '/home/guest',
      title: 'Needle in a haystack',
      brief: 'The log server. A backup agent printed its session token into the auth log, somewhere in 2,400 lines.',
      flag: F[1],
      lesson: 'grep turns thousands of lines into one. Secrets in logs are one of the most common real leaks.',
      hints: ['The interesting file is in /var/log.', 'Reading 2,400 lines by hand is not the way. grep searches files: help grep', 'Flags all start with NR{ ... try: grep NR /var/log/auth.log'],
      files: {
        '/home/guest/README.txt': 'needle: central syslog collector.\nLogs live where logs always live.\n',
        '/var/log/auth.log': authLog(F[1]),
        '/var/log/syslog': 'Nov  6 00:00:01 needle rsyslogd: [origin software="rsyslogd"] rsyslogd was HUPed\n',
        '/var/log/kern.log': 'Nov  6 00:00:00 needle kernel: [    0.000000] Linux version 6.8.0-nullroute\n'
      }
    },
    {
      id: 'courier', host: 'courier', user: 'guest', home: '/home/guest',
      title: 'Encoding is not encryption',
      brief: 'You intercepted a courier message. It looks scrambled, but it was only encoded. Maybe more than once.',
      flag: F[2],
      lesson: 'Base64 is a transport format, not protection. Anyone can reverse it, as many times as it was applied.',
      hints: ['Look at intercept.txt. The alphabet (A-Z, a-z, 0-9, +, /, =) is a giveaway. Try: file intercept.txt', 'Decode it with base64 -d intercept.txt', 'Still gibberish? Pipe it again: cat intercept.txt | base64 -d | base64 -d'],
      files: {
        '/home/guest/intercept.txt': util.b64encode(util.b64encode('Meet at dock 7 after midnight. Passphrase: ' + F[2] + '\n')).match(/.{1,64}/g).join('\n') + '\n',
        '/home/guest/README.txt': 'Captured from the courier relay at 02:14.\nThe courier said it was "encrypted twice". Couriers are not cryptographers.\n'
      }
    },
    {
      id: 'firmware', host: 'firmware', user: 'guest', home: '/home/guest',
      title: 'Strings attached',
      brief: 'A firmware image pulled off a Halcyon door controller. Binaries hide readable text, and the debug key looks... rotated.',
      flag: F[3],
      lesson: 'strings pulls readable text out of binaries; ROT13 is a toy cipher anyone can undo. Never ship debug keys in firmware.',
      hints: ['cat on a binary is noise. Try strings door-ctl.bin', 'One string looks like a key=value pair with scrambled letters, but the digits and braces survived.', 'Letters shifted by 13: strings door-ctl.bin | rot13'],
      files: {
        '/home/guest/door-ctl.bin': firmware('debug_key=' + F[3]),
        '/home/guest/README.txt': 'Dumped via SPI flash clip from door controller DC-04.\n'
      }
    },
    {
      id: 'gitleak', host: 'gitleak', user: 'dev', home: '/home/dev',
      title: 'Git never forgets',
      brief: 'A developer workstation. The team "removed" an API key from their web app repository last week.',
      flag: F[4],
      lesson: 'Deleting a secret in a new commit leaves it in history forever. Rotate leaked keys; do not just delete them.',
      hints: ['cd webapp and look around. It is a git repository.', 'git log shows the history. One commit message sounds guilty.', 'git show <hash> prints that commit\'s diff, including removed lines.'],
      files: {
        '/home/dev/webapp/app.py': 'import os\nfrom flask import Flask\n\napp = Flask(__name__)\nAPI_KEY = os.environ["API_KEY"]  # moved to env, much safer now\n\n@app.get("/")\ndef index():\n    return "halcyon internal"\n',
        '/home/dev/webapp/README.md': '# halcyon-webapp\n\nInternal dashboard. Copy .env.example to .env to run.\n',
        '/home/dev/webapp/.env.example': 'API_KEY=changeme\n',
        '/home/dev/webapp/.git/HEAD': 'ref: refs/heads/main\n',
        '/home/dev/webapp/.git/config': '[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = git@git.halcyon.local:web/halcyon-webapp.git\n',
        '/home/dev/todo.txt': '- ship dashboard\n- ask Ravi if removing the key in a commit is enough (it is, right?)\n'
      },
      git: {
        root: '/home/dev/webapp',
        commits: [
          { hash: '3e1f0c9a7b2d4e5f60718293a4b5c6d7e8f90123', author: 'Ravi Mehta <ravi@halcyon.local>', date: 'Mon Oct 26 10:12:44 2026 +0530', msg: 'initial dashboard',
            diff: 'diff --git a/app.py b/app.py\nnew file mode 100644\n+from flask import Flask\n+app = Flask(__name__)' },
          { hash: '9b7d21e4c3f5a6b7c8d9e0f1a2b3c4d5e6f70812', author: 'Ravi Mehta <ravi@halcyon.local>', date: 'Tue Oct 27 18:03:10 2026 +0530', msg: 'add config so prod works',
            diff: 'diff --git a/.env b/.env\nnew file mode 100644\n+API_KEY=' + F[4] + '\n+DEBUG=false' },
          { hash: 'c0ffee5d1e2a3b4c5d6e7f8091a2b3c4d5e6f7a8', author: 'Ravi Mehta <ravi@halcyon.local>', date: 'Wed Oct 28 09:41:57 2026 +0530', msg: 'remove secrets from repo (oops)',
            diff: 'diff --git a/.env b/.env\ndeleted file mode 100644\n-API_KEY=' + F[4] + '\n-DEBUG=false\n\ndiff --git a/app.py b/app.py\n-API_KEY = "hardcoded"\n+API_KEY = os.environ["API_KEY"]  # moved to env, much safer now' }
        ]
      }
    },
    {
      id: 'intranet', host: 'intranet', user: 'guest', home: '/home/guest',
      title: 'Robots, keep out',
      brief: 'From here you can reach the internal web server at http://intranet.halcyon.local/\nRecon first: what are search engines told not to look at?',
      flag: F[5],
      lesson: 'robots.txt is a public list of places a site would rather you did not look. It is a map, not a lock.',
      hints: ['curl http://intranet.halcyon.local/', 'Well-behaved crawlers read /robots.txt before crawling.', 'Visit the disallowed path, then the file inside it.'],
      files: {
        '/home/guest/README.txt': 'Reachable from this box:\n  http://intranet.halcyon.local/\nUse curl.\n'
      },
      http: {
        'intranet.halcyon.local': function (req) {
          var p = req.path.replace(/\/+$/, '') || '/';
          if (p === '/') return { status: 200, headers: { 'Content-Type': 'text/html' }, body: '<!doctype html>\n<title>Halcyon Intranet</title>\n<h1>Halcyon Intranet</h1>\n<p>Canteen menu, HR policies and the holiday calendar.</p>\n<!-- crawler rules updated by IT, see the usual place -->\n' };
          if (p === '/robots.txt') return { status: 200, body: 'User-agent: *\nDisallow: /hr/\nDisallow: /backup-7f3a/\n' };
          if (p === '/hr') return { status: 403, body: 'Forbidden' };
          if (p === '/backup-7f3a') return { status: 200, headers: { 'Content-Type': 'text/html' }, body: 'Index of /backup-7f3a/\n\n  ../\n  db_2026-11-01.sql.bak    3.1K\n' };
          if (p === '/backup-7f3a/db_2026-11-01.sql.bak') return { status: 200, body: '-- MySQL dump 10.13\n-- Host: localhost  Database: intranet\nINSERT INTO settings VALUES (\'site_name\',\'Halcyon Intranet\');\nINSERT INTO settings VALUES (\'maintenance_token\',\'' + F[5] + '\');\n' };
          return { status: 404, body: 'Not Found' };
        }
      }
    },
    {
      id: 'tokens', host: 'tokens', user: 'guest', home: '/home/guest',
      title: 'alg: none',
      brief: 'The API at http://api.halcyon.local/ has an /admin endpoint. You have a guest session token.\nIt is signed... or is it?',
      flag: F[6],
      lesson: 'A JWT is just base64url JSON. Servers must pin the expected algorithm and never accept "alg":"none".',
      hints: ['curl http://api.halcyon.local/ and read session.txt. Send it with: curl -H "Authorization: Bearer <token>" http://api.halcyon.local/whoami',
        'A JWT is header.payload.signature, each base64url. Decode them: cut -d. -f1 session.txt | base64url -d   (and -f2)',
        'You cannot sign as admin without the secret, but you can claim no signature is needed. Build a header with alg "none": echo -n \'{"alg":"none","typ":"JWT"}\' | base64url',
        'Do the same for a payload with "role":"admin", then join them as HEADER.PAYLOAD. (keep the trailing dot) and call /admin.'],
      files: {
        '/home/guest/session.txt': ORIGINAL_JWT + '\n',
        '/home/guest/README.txt': 'Your session token is in session.txt.\nAPI docs: curl http://api.halcyon.local/\n'
      },
      http: { 'api.halcyon.local': apiSite(F[6]) }
    },
    {
      id: 'shop', host: 'shop', user: 'guest', home: '/home/guest',
      title: 'Bobby Tables',
      brief: 'The staff shop at http://shop.halcyon.local/ has an admin account. You do not know its password.\nYou do not need to.',
      flag: F[7],
      lesson: 'Building SQL by gluing strings lets input become code. Parameterised queries make this whole class of bug impossible.',
      hints: ['Read the page source: curl http://shop.halcyon.local/. A developer left a debug switch.', 'Try a login with &debug=1 to see the exact SQL. Wrap URLs in double quotes so the shell leaves \' alone.',
        'Your input lands inside username=\'...\'. Close the quote and comment out the rest: user=admin\'--',
        'curl "http://shop.halcyon.local/login?user=admin\'--&pass=x"'],
      files: {
        '/home/guest/README.txt': 'Target: http://shop.halcyon.local/\nGoal: log in as admin.\n'
      },
      http: { 'shop.halcyon.local': shopSite(F[7]) }
    },
    {
      id: 'vault', host: 'vault', user: 'guest', home: '/home/guest', homes: { admin: '/root' },
      title: 'Password spray',
      brief: 'The vault server. The flag is in /root, readable only by admin. Somebody left a backup of the password file lying around.',
      flag: F[8],
      lesson: 'Fast unsalted hashes of human passwords fall to a wordlist in seconds. Use bcrypt/argon2 and long passphrases.',
      hints: ['find / -name "*.bak"', 'The admin line contains a SHA-256 hash after $sha256$. There is a wordlist in /usr/share/wordlists.', 'crack -w /usr/share/wordlists/common.txt <hash>   then   su admin <password>   then look in /root'],
      users: { admin: VAULT_PASSWORD },
      files: {
        '/home/guest/README.txt': 'vault: secrets storage. Flag is root-only (well, admin-only).\n',
        '/var/backups/shadow.bak': 'root:!:20398:0:99999:7:::\nadmin:$sha256$' + util.sha256(VAULT_PASSWORD) + ':20398:0:99999:7:::\nguest:$sha256$' + util.sha256('guest') + ':20398:0:99999:7:::\n',
        '/usr/share/wordlists/common.txt': WORDS.join('\n') + '\n',
        '/root/': { owner: 'admin' },
        '/root/flag.txt': { content: F[8] + '\n', owner: 'admin' },
        '/root/.motd': { content: 'You should not be here. Unless you are admin.\n', owner: 'admin' }
      }
    },
    {
      id: 'billing', host: 'billing', user: 'guest', home: '/home/guest',
      title: 'Off by one account',
      brief: 'The billing portal at http://billing.halcyon.local/ shows you your own invoice. The URL has a number in it.\nYours is #1007. The server never checks whose invoice you asked for.',
      flag: F[10],
      lesson: 'Never let a client-supplied ID stand in for proof of ownership. Check that the logged-in user actually owns the object (authorization) on every request. This bug class is IDOR.',
      hints: ['curl http://billing.halcyon.local/ and read your account id.', 'Fetch your own first: curl "http://billing.halcyon.local/invoice?id=1007". Then change the number.', 'Finance is account #1000. Try id=1000.'],
      files: {
        '/home/guest/README.txt': 'Billing portal: http://billing.halcyon.local/\nYou are logged in as account #1007 (contractor).\nInvoices: /invoice?id=<number>\n'
      },
      http: {
        'billing.halcyon.local': function (req) {
          var p = req.path.replace(/\/+$/, '') || '/';
          if (p === '/') return { status: 200, headers: { 'Content-Type': 'text/html' }, body: '<!doctype html>\n<title>Halcyon Billing</title>\n<h1>Your invoices</h1>\n<ul><li><a href="/invoice?id=1007">Invoice #1007</a></li></ul>\n<!-- accounts run 1000-1007; 1000 is finance -->\n' };
          if (p === '/invoice') {
            var id = parseInt(req.query.id, 10);
            if (!id) return { status: 400, body: 'usage: /invoice?id=<number>' };
            if (id === 1000) return { status: 200, body: 'Invoice #1000   account: finance (CFO)\nItem: Q4 security retainer\nAmount: 42000 INR\nInternal memo code: ' + F[10] + '\n' };
            var who = { 1001: 'Ravi Mehta', 1002: 'payroll', 1007: 'you (contractor)' }[id] || 'account ' + id;
            return { status: 200, body: 'Invoice #' + id + '   account: ' + who + '\nItem: monthly services\nAmount: 1800 INR\n' };
          }
          return { status: 404, body: 'Not Found' };
        }
      }
    },
    {
      id: 'archive', host: 'archive', user: 'guest', home: '/home/guest',
      title: 'Dot dot slash',
      brief: 'A document server at http://archive.halcyon.local/ serves files from its public folder.\nIt builds the path by gluing your filename onto the end, and never looks where that path ends up.',
      flag: F[11],
      lesson: 'Concatenating user input into a file path lets ../ climb out of the intended directory (path traversal). Canonicalise the resolved path and confirm it still sits inside the allowed root before opening it.',
      hints: ['curl http://archive.halcyon.local/ then fetch a listed doc: curl "http://archive.halcyon.local/get?file=welcome.txt"', 'The server opens /srv/public/ + whatever you pass. ../ walks up one directory.', 'There is a secrets file one level above public. Try file=../secret.txt'],
      files: {
        '/home/guest/README.txt': 'Document server: http://archive.halcyon.local/\nFetch docs with /get?file=<name>.\n'
      },
      http: {
        'archive.halcyon.local': function (req) {
          var p = req.path.replace(/\/+$/, '') || '/';
          if (p === '/') return { status: 200, headers: { 'Content-Type': 'text/html' }, body: '<!doctype html>\n<title>Halcyon Docs</title>\n<h1>Public documents</h1>\n<ul><li>welcome.txt</li><li>handbook.txt</li></ul>\n<p>Fetch: /get?file=welcome.txt</p>\n' };
          if (p === '/get') {
            var name = req.query.file;
            if (name == null) return { status: 400, body: 'usage: /get?file=<name>' };
            var base = ['srv', 'public']; // server root; path is resolved the naive way
            name.split('/').forEach(function (seg) {
              if (seg === '' || seg === '.') return;
              if (seg === '..') base.pop(); else base.push(seg);
            });
            var abs = '/' + base.join('/');
            var tree = {
              '/srv/public/welcome.txt': 'Welcome to the Halcyon document archive.\n',
              '/srv/public/handbook.txt': 'Staff handbook: be excellent to each other.\n',
              '/srv/secret.txt': 'Restricted — keep above the public root.\nrecovery_code=' + F[11] + '\n',
              '/etc/passwd': 'root:x:0:0:root:/root:/bin/bash\nravi:x:1001:1001:Ravi Mehta:/home/ravi:/bin/bash\n'
            };
            if (tree[abs] != null) return { status: 200, body: tree[abs] };
            return { status: 404, body: 'No such file: ' + abs };
          }
          return { status: 404, body: 'Not Found' };
        }
      }
    },
    {
      id: 'blackbox', host: 'blackbox', user: 'guest', home: '/home/guest',
      title: 'Known plaintext',
      brief: 'The last machine. A final transmission, XOR-encrypted with a single secret byte.\nYou know one thing for sure: it contains a flag, and every flag starts with NR{',
      flag: F[9],
      lesson: 'Single-byte XOR has only 255 keys. With brute force or one known character the whole message falls.',
      hints: ['transmission.hex is hex-encoded ciphertext. help xor', 'With only 255 possible keys you can just try them all: xor -b transmission.hex', 'Or be clever: ciphertext byte XOR known plaintext byte = key. Then xor -k <key> transmission.hex'],
      files: {
        '/home/guest/transmission.hex': hex,
        '/home/guest/README.txt': 'Intercepted on the satellite uplink. Single-byte XOR, says the analyst.\n'
      }
    }
  ];
});
