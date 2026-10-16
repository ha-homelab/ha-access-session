#!/usr/bin/env node
/** Real embedded demo with synthetic same-origin session responses; no HA/IdP calls. */
const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const http = require('node:http')
const crypto = require('node:crypto')
const { setTimeout: delay } = require('node:timers/promises')
const root = path.resolve(__dirname, '..')
const directory = path.join(root, 'gateway/web')
const output = path.resolve(process.env.CI_BROWSER_DIAGNOSTICS || '.compatibility/local')
const evidence = path.resolve(process.env.CI_BROWSER_EVIDENCE || path.join(output, 'result.json'))
const engine = process.env.CI_BROWSER_ENGINE || 'chromium'
const channel = process.env.CI_BROWSER_CHANNEL || ''
assert(process.env.CI_PLAYWRIGHT_MODULE && path.isAbsolute(process.env.CI_PLAYWRIGHT_MODULE))
assert(['chromium', 'firefox', 'webkit'].includes(engine))
const playwright = require(process.env.CI_PLAYWRIGHT_MODULE)
fs.mkdirSync(output, { recursive: true })
fs.rmSync(evidence, { force: true })
const assets = new Map()
for (const name of ['index.html', 'app.js', 'style.css']) {
  const file = path.join(directory, name)
  assert(fs.lstatSync(file).isFile() && !fs.lstatSync(file).isSymbolicLink())
  assets.set(`/${name}`, fs.readFileSync(file))
}
const pending = [], requests = [], unexpected = [], errors = [], logs = [], scenarios = []
const mime = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css' }
const server = http.createServer((request, response) => {
  const url = new URL(request.url, 'http://localhost')
  if (url.pathname === '/session/ha') {
    const body = []
    request.on('data', data => body.push(data))
    request.on('end', () => {
      requests.push({ path: request.url, method: request.method, bytes: Buffer.concat(body).length })
      const item = pending.shift()
      if (!item) { unexpected.push(request.url); response.writeHead(500).end(); return }
      item.response = response
      item.send = () => {
        if (!response.headersSent) response.writeHead(item.status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' })
        response.end(item.status === 204 ? undefined : JSON.stringify(item.body).slice(item.bodyPrefix?.length || 0))
      }
      if (!item.deferred) item.send()
    })
    return
  }
  const route = url.pathname === '/' ? '/index.html' : url.pathname
  const bytes = assets.get(route)
  if (!bytes) { response.writeHead(404).end(); return }
  response.writeHead(200, { 'Content-Type': mime[path.extname(route)], 'Cache-Control': 'no-store' })
  response.end(bytes)
})
const tokenA = 'synthetic-fixture-token-alpha'
const tokenB = 'synthetic-fixture-token-beta'
const session = (token = tokenA, expires = 300) => ({ contract_version: 1, access_token: token, expires_in: expires })
function queue(body = session(), status = 200, deferred = false) {
  const item = { body, status, deferred }
  pending.push(item)
  return item
}
async function accepted(item) {
  const deadline = Date.now() + 10000
  while (!item.response && Date.now() < deadline) await delay(20)
  assert(item.response, 'The expected session request did not reach the synthetic server')
}
async function main() {
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
  const origin = `http://127.0.0.1:${server.address().port}`
  let browser, context, page
  try {
    assert.deepEqual(await Promise.all(['/go.mod', '/.git/config', '/%2e%2e%2fgo.mod'].map(async route => (await fetch(origin + route)).status)), [404, 404, 404])
    browser = await playwright[engine].launch({ headless: true, ...(channel ? { channel } : {}) })
    context = await browser.newContext({ viewport: { width: 1280, height: 900 }, serviceWorkers: 'block' })
    context.setDefaultTimeout(10000)
    await context.tracing.start({ screenshots: true, snapshots: true, sources: true })
    await context.route('**/*', route => {
      if (new URL(route.request().url()).origin === origin) return route.continue()
      unexpected.push(route.request().url()); return route.abort()
    })
    page = await context.newPage()
    page.on('pageerror', error => errors.push(String(error)))
    page.on('console', message => logs.push(message.text()))
    const create = () => page.getByRole('button', { name: 'Create real session', exact: true }).click()
    const revoke = () => page.getByRole('button', { name: 'Revoke session', exact: true }).click()
    const preview = () => page.getByRole('button', { name: 'Preview session', exact: true }).click()
    const status = text => page.locator('#status').filter({ hasText: text }).waitFor()
    const noCredential = async () => assert(await page.evaluate(() => accessToken === null), 'Credential must have been discarded')
    async function flush(item, receivedResponse = null) {
      await accepted(item)
      const received = receivedResponse ? Promise.resolve(receivedResponse) : page.waitForResponse(response => response.url().startsWith(origin + '/session/ha'))
      item.send()
      await received
      if (receivedResponse) await receivedResponse.finished()
      // Drain response/body promise continuations before inspecting unchanged UI state.
      await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))))
    }
    async function scenario(name, run) {
      await page.goto(origin)
      await status('Ready to explore')
      await run()
      assert.deepEqual(errors, [])
      assert.deepEqual(unexpected, [])
      assert.equal(pending.length, 0, 'Every declared response must be consumed')
      scenarios.push(name)
      console.log(`PASS ${name}`)
    }
    await scenario('preview is local and never retains a session credential', async () => {
      const before = requests.length
      await preview(); await status('Demo session verified'); await noCredential()
      assert.equal(requests.length, before)
    })
    await scenario('successful exchange retains credentials only in memory', async () => {
      queue(); await create(); await status('Home Assistant session created')
      assert(await page.evaluate(() => accessToken !== null))
      assert.equal(await page.locator('#lifetime').innerText(), '300 seconds')
      assert.deepEqual(await page.evaluate(() => [localStorage.length, sessionStorage.length, document.cookie]), [0, 0, ''])
      assert(!(await page.locator('body').innerText()).includes(tokenA))
      assert(!page.url().includes(tokenA))
    })
    await scenario('malformed and overlong session contracts fail closed', async () => {
      for (const malformed of [session('', 300), session(tokenA, 301), session(tokenA, 0), session(tokenA, 1.5), { ...session(), contract_version: 2 }]) {
        await preview(); await status('Demo session verified')
        queue(malformed); await create(); await status('Session unavailable'); await noCredential()
      }
    })
    await scenario('denied exchange clears an earlier credential', async () => {
      queue(); await create(); await status('Home Assistant session created')
      queue({ error: 'synthetic denial' }, 401); await create(); await status('Session unavailable'); await noCredential()
    })
    await scenario('confirmed revocation clears the local session', async () => {
      queue(); await create(); await status('Home Assistant session created')
      queue(null, 204); await revoke(); await status('Session revoked'); await noCredential()
      assert.equal(requests.at(-1).path, '/session/ha?revoke=1')
    })
    await scenario('late exchange cannot restore a revoked credential', async () => {
      const old = queue(session(), 200, true); await create(); await accepted(old)
      queue(null, 204); await revoke(); await status('Session revoked')
      await flush(old); await noCredential(); assert.equal(await page.locator('#status').innerText(), 'Session revoked')
    })
    await scenario('delayed JSON body cannot restore a credential after revocation', async () => {
      const old = queue(session(), 200, true); await create(); await accepted(old)
      const headersReceived = page.waitForResponse(response => response.url() === origin + '/session/ha')
      old.response.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' })
      old.bodyPrefix = '{'
      old.response.write(old.bodyPrefix)
      const received = await headersReceived
      queue(null, 204); await revoke(); await status('Session revoked')
      await flush(old, received); await noCredential(); assert.equal(await page.locator('#status').innerText(), 'Session revoked')
    })
    await scenario('out of order exchanges cannot replace the newest credential', async () => {
      const old = queue(session(tokenA), 200, true); await create(); await accepted(old)
      queue(session(tokenB)); await create(); await status('Home Assistant session created')
      await flush(old)
      assert(await page.evaluate(expected => accessToken === expected, tokenB))
    })
    await scenario('failed revocation still clears local credential and rejects late exchange', async () => {
      const old = queue(session(), 200, true); await create(); await accepted(old)
      queue({ error: 'synthetic failure' }, 503); await revoke(); await status('Local credential cleared')
      await flush(old); await noCredential(); assert.equal(await page.locator('#status').innerText(), 'Local credential cleared')
    })
    await scenario('new UI intent never aborts the server revocation request', async () => {
      const old = queue(null, 204, true); await revoke(); await accepted(old)
      await preview(); await status('Demo session verified')
      assert(!old.response.destroyed, 'Revocation must remain live at the server')
      await flush(old); await noCredential(); assert.equal(await page.locator('#status').innerText(), 'Demo session verified')
    })
    await scenario('short credential expiry clears memory and reports expired state', async () => {
      queue(session(tokenA, 1)); await create(); await status('Home Assistant session created')
      await status('Session expired'); await noCredential()
      assert.match(await page.locator('#detail').innerText(), /No credential is retained/)
    })
    await scenario('pagehide invalidates an in flight exchange', async () => {
      const old = queue(session(), 200, true); await create(); await accepted(old)
      await page.evaluate(() => window.dispatchEvent(new Event('pagehide')))
      await flush(old); await noCredential()
      assert.notEqual(await page.locator('#status').innerText(), 'Home Assistant session created')
    })
    await scenario('preview invalidates an in flight exchange and remains synthetic', async () => {
      const old = queue(session(), 200, true); await create(); await accepted(old)
      await preview(); await status('Demo session verified')
      await flush(old); await noCredential(); assert.equal(await page.locator('#status').innerText(), 'Demo session verified')
    })
    await scenario('narrow viewport retains accessible session controls', async () => {
      await page.setViewportSize({ width: 390, height: 844 })
      await preview(); await status('Demo session verified')
      for (const name of ['Preview session', 'Create real session', 'Revoke session']) assert(await page.getByRole('button', { name, exact: true }).isVisible())
      assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth))
    })
    assert(requests.every(request => request.method === 'POST' && request.bytes === 0 && ['/session/ha', '/session/ha?revoke=1'].includes(request.path)))
    assert(logs.every(line => !line.includes(tokenA) && !line.includes(tokenB)), 'Synthetic credentials must not be logged')
    const runtimeFile = path.join(output, 'runtime.json')
    const runtime = fs.existsSync(runtimeFile) ? JSON.parse(fs.readFileSync(runtimeFile, 'utf8')) : {
      schema: 1, target: process.env.CI_BROWSER_TARGET_ID || 'local', engine, channel,
      playwrightVersion: require(path.join(process.env.CI_PLAYWRIGHT_MODULE, 'package.json')).version,
      platform: process.platform, sourceSha: process.env.GITHUB_SHA || 'local',
      runId: process.env.GITHUB_RUN_ID || 'local', runAttempt: process.env.GITHUB_RUN_ATTEMPT || '1',
    }
    fs.writeFileSync(evidence, JSON.stringify({ ...runtime, engine: browser.browserType().name(), browserVersion: browser.version(), testsPassed: scenarios.length, testsFailed: 0, scenarios,
      applicationFiles: Object.fromEntries([...assets].map(([name, bytes]) => [name, crypto.createHash('sha256').update(bytes).digest('hex')])) }, null, 2) + '\n')
    await page.screenshot({ path: path.join(output, 'application.png'), fullPage: true })
  } finally {
    if (context) { await context.tracing.stop({ path: path.join(output, 'trace.zip') }); await context.close() }
    if (browser) await browser.close()
    server.closeAllConnections()
    await new Promise(resolve => server.close(resolve))
  }
}
main().catch(error => { console.error(error); process.exitCode = 1 })
