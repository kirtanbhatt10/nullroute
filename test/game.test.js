'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const Shell = require('../shell.js');
const buildLevels = require('../levels.js');

function memStorage() {
  const m = {};
  return { getItem: (k) => (k in m ? m[k] : null), setItem: (k, v) => { m[k] = String(v); }, _m: m };
}

function newGame(storage) {
  return Shell.createGame({ levels: buildLevels(Shell.util), storage: storage || memStorage() });
}

const run = (g, line) => g.exec(line).lines.map((l) => l.text).join('\n');
const flagIn = (s) => (s.match(/NR\{[^}\s]+\}/) || [])[0];

function solveAndSubmit(g, flag) {
  const out = run(g, 'submit ' + flag);
  assert.match(out, /FLAG ACCEPTED/, 'submit failed: ' + out);
}

test('sha256 matches node:crypto', () => {
  for (const s of ['', 'abc', 'nightingale7', 'x'.repeat(55), 'x'.repeat(56), 'x'.repeat(64), 'y'.repeat(1000)]) {
    assert.equal(Shell.util.sha256(s), crypto.createHash('sha256').update(s, 'latin1').digest('hex'));
  }
});

test('base64 and base64url round-trip and match Buffer', () => {
  for (const s of ['', 'a', 'ab', 'abc', '{"alg":"none"}', 'hello?>~~']) {
    assert.equal(Shell.util.b64encode(s), Buffer.from(s, 'latin1').toString('base64'));
    assert.equal(Shell.util.b64encode(s, true), Buffer.from(s, 'latin1').toString('base64url'));
    assert.equal(Shell.util.b64decode(Shell.util.b64encode(s)), s);
  }
});

test('tokenizer handles quotes, escapes and pipes', () => {
  assert.deepEqual(Shell.tokenize('echo "a b" c\\ d \'e"f\''), ['echo', 'a b', 'c d', 'e"f']);
  const t = Shell.tokenize('cat x|grep y');
  assert.equal(t.length, 5);
  assert.equal(t[2].pipe, true);
  assert.throws(() => Shell.tokenize('echo "oops'));
});

test('level 1 gate: hidden dotfile', () => {
  const g = newGame();
  assert.doesNotMatch(run(g, 'ls'), /\.flag/);
  assert.match(run(g, 'ls -a'), /\.flag/);
  solveAndSubmit(g, flagIn(run(g, 'cat .flag')));
});

test('locked targets refuse ssh until previous is rooted', () => {
  const g = newGame();
  assert.match(run(g, 'ssh needle'), /Connection refused/);
  solveAndSubmit(g, flagIn(run(g, 'cat .flag')));
  assert.match(run(g, 'ssh needle'), /Connected to needle/);
});

test('full playthrough: every level is solvable the intended way', () => {
  const g = newGame();
  solveAndSubmit(g, flagIn(run(g, 'cat ~/.flag')));

  run(g, 'ssh needle');
  const grep = run(g, 'grep NR /var/log/auth.log');
  assert.equal(grep.split('\n').length, 1);
  solveAndSubmit(g, flagIn(grep));

  run(g, 'ssh courier');
  assert.match(run(g, 'file intercept.txt'), /base64/);
  assert.equal(flagIn(run(g, 'base64 -d intercept.txt')), undefined);
  solveAndSubmit(g, flagIn(run(g, 'cat intercept.txt | base64 -d | base64 -d')));

  run(g, 'ssh firmware');
  assert.equal(flagIn(run(g, 'cat door-ctl.bin')), undefined);
  const s = run(g, 'strings door-ctl.bin | rot13 | grep debug_key');
  solveAndSubmit(g, flagIn(s));

  run(g, 'ssh gitleak');
  assert.match(run(g, 'git log'), /not a git repository/);
  run(g, 'cd webapp');
  const log = run(g, 'git log --oneline');
  assert.match(log, /remove secrets/);
  const hash = log.split('\n').find((l) => /add config/.test(l)).split(' ')[0];
  solveAndSubmit(g, flagIn(run(g, 'git show ' + hash)));

  run(g, 'ssh intranet');
  const robots = run(g, 'curl http://intranet.halcyon.local/robots.txt');
  const dir = robots.match(/Disallow: (\/backup-[^\s]+)/)[1];
  const listing = run(g, 'curl http://intranet.halcyon.local' + dir);
  const file = listing.match(/(db_\S+\.bak)/)[1];
  solveAndSubmit(g, flagIn(run(g, 'curl intranet.halcyon.local' + dir + file)));

  run(g, 'ssh tokens');
  const tok = run(g, 'cat session.txt').trim();
  assert.match(run(g, 'curl -H "Authorization: Bearer ' + tok + '" http://api.halcyon.local/admin'), /admins only/);
  assert.match(run(g, 'cut -d. -f2 session.txt | base64url -d'), /"role":"user"/);
  const h = run(g, 'echo -n \'{"alg":"none","typ":"JWT"}\' | base64url').trim();
  const p = run(g, 'echo -n \'{"sub":"guest","role":"admin"}\' | base64url').trim();
  // Tampering with an HS256 token must fail
  const tampered = tok.split('.')[0] + '.' + p + '.' + tok.split('.')[2];
  assert.match(run(g, 'curl -H "Authorization: Bearer ' + tampered + '" http://api.halcyon.local/admin'), /invalid signature/);
  solveAndSubmit(g, flagIn(run(g, 'curl -H "Authorization: Bearer ' + h + '.' + p + '." http://api.halcyon.local/admin')));

  run(g, 'ssh shop');
  assert.match(run(g, 'curl "http://shop.halcyon.local/login?user=admin&pass=guess&debug=1"'), /SELECT \* FROM staff WHERE username='admin' AND password='guess'/);
  assert.match(run(g, 'curl "http://shop.halcyon.local/login?user=admin\'&pass=x"'), /SQL error/);
  assert.match(run(g, 'curl "http://shop.halcyon.local/login?user=bob\'--&pass=x"'), /Login failed/);
  assert.ok(flagIn(run(g, 'curl "http://shop.halcyon.local/login?user=x&pass=\' OR \'1\'=\'1"')));
  solveAndSubmit(g, flagIn(run(g, 'curl "http://shop.halcyon.local/login?user=admin\'--&pass=x"')));

  run(g, 'ssh vault');
  assert.match(run(g, 'cat /root/flag.txt'), /Permission denied/);
  assert.match(run(g, 'find / -name "*.bak"'), /shadow\.bak/);
  const hashLine = run(g, 'grep admin /var/backups/shadow.bak');
  const sha = hashLine.split(':')[1].replace('$sha256$', '');
  const cracked = run(g, 'crack -w /usr/share/wordlists/common.txt ' + sha);
  const pw = cracked.match(/cracked after \d+ tries: (\S+)/)[1];
  assert.match(run(g, 'su admin wrong'), /Authentication failure/);
  assert.match(run(g, 'su admin ' + pw), /now admin/);
  assert.equal(g._state().cwd, '/root');
  solveAndSubmit(g, flagIn(run(g, 'cat flag.txt')));
  run(g, 'exit');
  assert.equal(g._state().user, 'guest');

  run(g, 'ssh billing');
  assert.match(run(g, 'curl "http://billing.halcyon.local/invoice?id=1007"'), /contractor/);
  solveAndSubmit(g, flagIn(run(g, 'curl "http://billing.halcyon.local/invoice?id=1000"')));

  run(g, 'ssh archive');
  assert.match(run(g, 'curl "http://archive.halcyon.local/get?file=welcome.txt"'), /document archive/);
  solveAndSubmit(g, flagIn(run(g, 'curl "http://archive.halcyon.local/get?file=../secret.txt"')));

  run(g, 'ssh blackbox');
  assert.equal(flagIn(run(g, 'cat transmission.hex')), undefined);
  const brute = run(g, 'xor -b transmission.hex');
  assert.ok(flagIn(brute), 'brute force should reveal the flag in the top candidates');
  const first = parseInt(run(g, 'head -n 1 transmission.hex').split(' ')[0], 16);
  const key = (first ^ 'T'.charCodeAt(0)).toString(16);
  const out = run(g, 'submit ' + flagIn(run(g, 'xor -k ' + key + ' transmission.hex')));
  assert.match(out, /ALL 12 TARGETS ROOTED/);
  assert.equal(g.progress().solved, 12);
});

test('wrong flags are rejected, cross-level flags are explained', () => {
  const g = newGame();
  assert.match(run(g, 'submit NR{nope}'), /Incorrect flag/);
  assert.match(run(g, 'submit NR{gr3p_th3_h4yst4ck}'), /belongs to needle/);
});

test('progress persists through storage', () => {
  const st = memStorage();
  const g1 = newGame(st);
  solveAndSubmit(g1, flagIn(run(g1, 'cat .flag')));
  run(g1, 'ssh needle');
  const g2 = newGame(st);
  assert.equal(g2.progress().solved, 1);
  assert.equal(g2.progress().host, 'needle');
  run(g2, 'reset --yes');
  assert.equal(newGame(st).progress().solved, 0);
});

test('corrupted storage does not crash', () => {
  const st = memStorage();
  st.setItem('nullroute.v1', '{not json');
  assert.equal(newGame(st).progress().solved, 0);
});

test('hints are progressive and finite', () => {
  const g = newGame();
  assert.match(run(g, 'hint'), /hint 1\/3/);
  run(g, 'hint'); run(g, 'hint');
  assert.match(run(g, 'hint'), /No more hints/);
});

test('core commands behave like Unix', () => {
  const g = newGame();
  assert.equal(run(g, 'pwd'), '/home/guest');
  run(g, 'cd /etc');
  assert.equal(run(g, 'cat hostname'), 'gate');
  run(g, 'cd');
  assert.equal(run(g, 'pwd'), '/home/guest');
  assert.equal(run(g, 'echo hello world | wc -l'), '1');
  assert.equal(run(g, 'echo -n abc | sha256sum'), crypto.createHash('sha256').update('abc').digest('hex') + '  -');
  assert.equal(run(g, 'echo SGVsbG8= | base64 -d'), 'Hello');
  assert.equal(run(g, 'echo Uryyb | rot13'), 'Hello');
  assert.match(run(g, 'cat nope.txt'), /No such file/);
  assert.match(run(g, 'frobnicate'), /command not found/);
  assert.match(run(g, 'cat | | x'), /syntax error/);
  assert.match(run(g, 'sudo su'), /sudoers/);
  assert.match(run(g, 'grep -c todo notes.txt'), /^1$/);
  assert.match(run(g, 'ls -la'), /\.bash_history/);
  assert.equal(g.exec('clear').clear, true);
});

test('tab completion completes commands, paths and hosts', () => {
  const g = newGame();
  assert.equal(g.complete('subm').line, 'submit ');
  assert.equal(g.complete('cat REA').line, 'cat README.txt ');
  assert.equal(g.complete('cat .fl').line, 'cat .flag ');
  assert.equal(g.complete('ssh ga').line, 'ssh gate ');
  assert.equal(g.complete('ssh ne').line, 'ssh ne', 'locked hosts are not suggested');
});

test('prompt reflects user, host and path', () => {
  const g = newGame();
  assert.equal(g.prompt(), 'guest@gate:~$');
  run(g, 'cd /etc');
  assert.equal(g.prompt(), 'guest@gate:/etc$');
});

test('welcome screen renders', () => {
  const lines = newGame().welcome();
  assert.ok(lines.length > 5);
  assert.ok(lines.some((l) => /Twelve machines/.test(l.text)));
});

const mentorLines = (g, line) => g.exec(line).lines.filter((l) => l.cls === 'mentor').map((l) => l.text).join('\n');

test('mentor: on-demand guide explains the goal and adapts the next move', () => {
  const g = newGame();
  const guide = run(g, 'mentor');
  assert.match(guide, /target 1\/12/);
  assert.match(guide, /Your next move[\s\S]*ls lists the files/);
  run(g, 'ls');
  assert.match(run(g, 'mentor next'), /help ls/);
  run(g, 'ls -a');
  assert.match(run(g, 'mentor next'), /cat <name>/);
});

test('mentor: never prints a flag, on any target', () => {
  const levels = buildLevels(Shell.util);
  const st = memStorage();
  st.setItem('nullroute.v1', JSON.stringify({ solved: Object.fromEntries(levels.map((l) => [l.id, true])), current: 0 }));
  const g = newGame(st);
  levels.forEach((l, i) => {
    run(g, 'ssh ' + l.host);
    const text = [run(g, 'mentor'), run(g, 'mentor next'), run(g, 'mentor basics')].join('\n');
    assert.ok(!text.includes(l.flag), 'mentor leaked the flag on ' + l.host);
    assert.ok(l.mentor && l.mentor.concept && l.mentor.steps.length, 'target ' + (i + 1) + ' has mentor guidance');
  });
});

test('mentor: teaches commands and rejects unknown topics', () => {
  const g = newGame();
  assert.match(run(g, 'mentor grep'), /Examples[\s\S]*grep -r/);
  assert.match(run(g, 'mentor pipes'), /\|/);
  assert.match(run(g, 'mentor xyzzy'), /nothing on "xyzzy"/);
  assert.match(run(g, 'help mentor'), /mentor \[on\|off/);
  assert.equal(g.complete('mentor base6').line, 'mentor base64');
  assert.equal(g.complete('mentor basi').line, 'mentor basics ');
});

test('mentor: coach mode is opt-in, persists, and reacts to play', () => {
  const st = memStorage();
  const g = newGame(st);
  assert.equal(mentorLines(g, 'lss'), '', 'coach is silent until turned on');
  run(g, 'mentor on');
  assert.match(mentorLines(g, 'lss'), /Did you mean ls\?/);
  assert.match(mentorLines(g, 'cat nope.txt'), /Tab completes/);
  const flagTip = mentorLines(g, 'cat .flag');
  assert.match(flagTip, /submit/);
  assert.doesNotMatch(flagTip, /NR\{h1dd3n/, 'the tip must not repeat the flag');
  assert.match(mentorLines(g, 'submit NR{wrong}'), /Copy the flag exactly/);
  assert.match(mentorLines(g, 'submit ' + flagIn(run(g, 'cat .flag'))), /Well done/);
  assert.match(mentorLines(g, 'ssh needle'), /Briefing:[\s\S]*First move/);
  assert.match(mentorLines(g, 'grep flag /var/log/auth.log'), /decoy/);

  const g2 = newGame(st);
  assert.match(run(g2, 'mentor status'), /ON/, 'mentor setting survives a reload');
  run(g2, 'reset --yes');
  assert.match(run(g2, 'mentor status'), /ON/, 'reset wipes progress but keeps the preference');
  run(g2, 'mentor off');
  assert.equal(mentorLines(g2, 'lss'), '');
});

test('mentor: nudges a player who seems stuck', () => {
  const g = newGame();
  run(g, 'mentor on');
  let tip = '';
  for (let i = 0; i < 12 && !tip; i++) tip = mentorLines(g, 'pwd');
  assert.match(tip, /commands here\. Here is a nudge/);
});
