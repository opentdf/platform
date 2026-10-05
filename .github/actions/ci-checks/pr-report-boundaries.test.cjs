const { test } = require('node:test');
const assert = require('node:assert/strict');
const MarkdownIt = require('markdown-it');
const report = require('./pr-report.cjs');
const renderer = new MarkdownIt('commonmark', { html: true });

function actualComment(value) {
  const sections = Object.fromEntries(Object.entries(report.PRODUCERS).map(([id, [title]]) => [id,
    { title, status: 'passed', summary: '**Passed**', details: '[Results](https://github.com/opentdf/platform)' }]));
  Object.assign(sections.benchmarks, value);
  const source = report.render(Object.keys(report.PRODUCERS), sections, 'a'.repeat(40), null);
  const tokens = renderer.parse(source, {});
  const html = renderer.render(source);
  const headings = tokens.flatMap((token, index) => token.type === 'heading_open' && token.tag === 'h2' ? [tokens[index + 1].children.map(child => child.content).join('')] : []);
  assert.deepEqual(headings, ['Benchmarks — passed', 'Govulncheck — passed', 'X-Test — passed']);
  // Inspect rendered HTML, not just Markdown delimiters. A closing wrapper
  // swallowed into a code block is escaped text and will fail these counts.
  assert.equal((html.match(/<details>/g) || []).length, 3);
  assert.equal((html.match(/<\/details>/g) || []).length, 3);
  assert.match(html, /<strong>Passed<\/strong>/);
  assert.match(html, /<a href="https:\/\/github.com\/opentdf\/platform">Results<\/a>/);
  assert.ok(source.length < 60000);
  return { source, html, tokens };
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
  actualComment({ details: '```text\u2028info\nbody' });
  actualComment({ summary: '~~~text\u2029info\nbody' });
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
