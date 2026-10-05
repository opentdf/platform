const { test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const MarkdownIt = require('markdown-it');
const root = path.resolve(__dirname, '../../..');
const renderer = new MarkdownIt('commonmark', { html: true });
const render = String.raw`
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location('report', '.github/actions/pr-report/report.py')
report = importlib.util.module_from_spec(spec)
spec.loader.exec_module(report)
value = json.load(sys.stdin)
sections = {id: dict(title=title, status='passed', summary='**Passed**', details='[Results](https://github.com/opentdf/platform)') for id, (title, _) in report.PRODUCERS.items()}
sections['benchmarks'].update(value)
print(report.render(list(report.PRODUCERS), sections, 'a' * 40, None))
`;

function actualComment(value) {
  const result = spawnSync('python3', ['-c', render], {
    cwd: root, input: JSON.stringify(value), encoding: 'utf8',
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' }
  });
  assert.equal(result.status, 0, result.stderr);
  const tokens = renderer.parse(result.stdout, {});
  const html = renderer.render(result.stdout);
  const headings = tokens.flatMap((token, index) => token.type === 'heading_open' && token.tag === 'h2' ? [tokens[index + 1].children.map(child => child.content).join('')] : []);
  assert.deepEqual(headings, ['Benchmarks — passed', 'Govulncheck — passed', 'X-Test — passed']);
  // Inspect rendered HTML, not just Markdown delimiters. A closing wrapper
  // swallowed into a code block is escaped text and will fail these counts.
  assert.equal((html.match(/<details>/g) || []).length, 3);
  assert.equal((html.match(/<\/details>/g) || []).length, 3);
  assert.match(html, /<strong>Passed<\/strong>/);
  assert.match(html, /<a href="https:\/\/github.com\/opentdf\/platform">Results<\/a>/);
  assert.ok(result.stdout.length < 60000);
  return { source: result.stdout, html, tokens };
}

for (const fence of ['```', '~~~']) {
  test(`${fence} valid long fenced summary/details retain independent rendered boundaries after truncation`, () => {
    for (const field of ['summary', 'details']) {
      const value = `${fence}text\n${'x'.repeat(field === 'summary' ? 1600 : 9100)}\n${fence}`;
      const output = actualComment({ [field]: value });
      assert.match(output.html, /truncated; see workflow artifacts/);
    }
  });

  test(`${fence} unmatched, wrong-character, short or over-indented closers cannot consume publisher markup`, () => {
    const other = fence[0] === '`' ? '~~~' : '```';
    for (const tail of ['', `\n${other}`, `\n${fence.slice(1)}`, `\n    ${fence}`, `\n${fence} not-a-closer`]) {
      for (const field of ['summary', 'details']) {
        actualComment({ [field]: `   ${fence}text\nbody${tail}` });
      }
    }
    actualComment({ summary: `${fence}${fence[0]}text\nbody\n${fence}`, details: `${fence}text\nbody` });
  });

  test(`${fence} ordinary matched fences preserve code rendering and legal closing indentation/length`, () => {
    for (const [indent, close] of [['', `   ${fence}`], ['   ', fence], ['', fence + fence[0]], ['', fence + '\t']]) {
      const output = actualComment({ details: `${indent}${fence}text\nordinary code\n${close}` });
      assert.match(output.html, /<pre><code class="language-text">ordinary code\n<\/code><\/pre>/);
    }
  });
}

test('repair rechecks fence-like tail lines and respects invalid backtick info/indented code', () => {
  actualComment({ summary: '`````text\nbody\n```\n~~~\n```' });
  actualComment({ details: '```invalid`info\nbody\n```' });
  actualComment({ details: '    ```\n    indented code\n    ```' });
  actualComment({ details: '\t~~~\n\tindented code\n\t~~~' });
  actualComment({ details: '- item\n  ```text\n  code\n```' });
  actualComment({ details: '> ```text\n> quoted code\n```' });
});

test('very long delimiters stay bounded without appended delimiter-sized repairs', () => {
  for (const character of ['`', '~']) {
    const fence = character.repeat(4000);
    for (const field of ['summary', 'details']) {
      const output = actualComment({ [field]: `${fence}text\n${'x'.repeat(1500)}\n${fence}` });
      assert.ok(output.source.length < 11000);
    }
  }
});

test('raw HTML/marker/mention neutralization survives fence repair', () => {
  const output = actualComment({ details: '```text\n</details><script>alert(1)</script>\n<!-- opentdf-pr-report:v1 -->\n@someone' });
  assert.ok(!output.html.includes('<script>'));
  assert.equal((output.source.match(/<!-- opentdf-pr-report:v1 -->/g) || []).length, 1);
  assert.ok(!output.source.includes('@someone'));
});
