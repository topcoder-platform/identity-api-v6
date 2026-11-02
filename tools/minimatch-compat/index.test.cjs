const assert = require('node:assert/strict');
const { createRequire } = require('node:module');
const { spawnSync } = require('node:child_process');
const { test } = require('node:test');

const legacyRequire = createRequire(require.resolve('eslint'));
const match = legacyRequire('minimatch');

test('CSV consumers parse quoted fields through the patched parser', async () => {
  const rows = await new Promise((resolve, reject) => {
    require('csv').parse('name,email\n"Example, User",user@example.test\n', { columns: true },
      (error, records) => error ? reject(error) : resolve(records));
  });
  assert.deepEqual(rows, [{ name: 'Example, User', email: 'user@example.test' }]);
});

test('Newman resolves dynamic variables with the patched Faker dependency', async () => {
  const fs = require('node:fs');
  const path = require('node:path');
  const directory = fs.mkdtempSync(path.join(require('node:os').tmpdir(), 'newman-compat-'));
  const iterationData = path.join(directory, 'data.csv');
  fs.writeFileSync(iterationData, 'account\nexample-account\n');
  const newmanRequire = createRequire(require.resolve('newman'));
  const generators = newmanRequire('postman-collection/lib/superstring/dynamic-variables');
  for (const [name, { generator }] of Object.entries(generators)) {
    assert.equal(typeof generator, 'function', name);
    assert.notEqual(generator(), undefined, name);
  }
  const http = require('node:http');
  const server = http.createServer((request, response) => {
    assert.ok(new URL(request.url, 'http://localhost').searchParams.get('name'));
    assert.equal(new URL(request.url, 'http://localhost').searchParams.get('row'), 'example-account');
    response.end('ok');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const summary = await new Promise((resolve, reject) => {
      require('newman').run({ collection: {
        info: { name: 'dependency smoke', schema: 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json' },
        item: [{ name: 'dynamic name', request: {
          method: 'GET', url: `http://127.0.0.1:${server.address().port}/?name={{$randomFirstName}}&row={{account}}`,
        } }],
      }, iterationData, timeoutRequest: 3000 }, (error, result) => error ? reject(error) : resolve(result));
    });
    assert.deepEqual(summary.run.failures, []);
    const requestUrl = summary.run.executions[0].request.url.toString();
    assert.equal(requestUrl.includes('$randomFirstName'), false);
  } finally {
    await new Promise(resolve => server.close(resolve));
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('legacy consumers retain the callable minimatch API', () => {
  assert.equal(typeof match, 'function');
  assert.equal(match('src/main.ts', '**/*.ts'), true);
  assert.equal(match('src/main.js', '**/*.ts'), false);
  assert.equal(match('.env', '*'), false);
  assert.equal(match.defaults({ dot: true })('.env', '*'), true);
  assert.deepEqual(match.match(['a.ts', 'b.js'], '*.ts'), ['a.ts']);
  assert.deepEqual(['a.ts', 'b.js'].filter(match.filter('*.ts')), ['a.ts']);
  assert.deepEqual(match.braceExpand('*.{js,ts}'), ['*.js', '*.ts']);
  assert.equal(new match.Minimatch('**/*.ts').match('src/main.ts'), true);
  assert.equal(match.Minimatch.defaults({ dot: true }) !== undefined, true);
  assert.equal(typeof match.GLOBSTAR, 'symbol');
});

test('installed glob discovers source files with patched matching', () => {
  const fs = require('node:fs');
  const path = require('node:path');
  const entries = fs.readdirSync('node_modules/.pnpm');
  const entry = entries.find(p => p.startsWith('glob@7.')) || entries.find(p => p.startsWith('glob@14.'));
  assert.ok(entry, 'Expected an installed glob consumer');
  const glob = require(path.resolve('node_modules/.pnpm', entry, 'node_modules/glob'));
  assert.ok(glob.sync('src/**/*.ts').includes('src/main.ts'));
});

test('amplifying glob patterns terminate within a bounded time', () => {
  const result = spawnSync(process.execPath, ['-e', `
    const match = require(${JSON.stringify(legacyRequire.resolve('minimatch'))});
    new match.Minimatch('**/../'.repeat(30) + '*.ts', { optimizationLevel: 2 });
  `], { timeout: 5000, encoding: 'utf8' });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0, result.stderr);
});
