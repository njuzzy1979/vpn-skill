// bootstrap.js — 内核引导链（§3.1）：三通道池（①直连 ②gh-proxy.com 前缀 ③127.0.0.1:7890 借道）
// 每通道 HEAD 探活+8s 超时 → release 元数据 → windows-amd64 稳定版 zip 下载 → SHA256 校验
// → 手写 zip 解压（零 npm 依赖）→ -v CLI 语义验证（r1 教训）→ bin/ 轮转落位 → kernel.json
// [VERIFY 实测结论] mihomo release 无官方 checksums 资产（仅各平台 zip+源码包）——按任务书降级为
// 双通道交叉 SHA256 一致性校验（两条独立通道同哈希）；第二通道不可用时单通道+警告（rc=2）
'use strict';

const fs = require('fs');
const http = require('http');
const path = require('path');
const tls = require('tls');
const zlib = require('zlib');
const https = require('https');
const crypto = require('crypto');
const { spawn } = require('child_process');

const util = require('./util');

const REPO = 'MetaCubeX/mihomo';
const RELEASE_PAGE_URL = 'https://github.com/' + REPO + '/releases/latest';
const API_LATEST = 'https://api.github.com/repos/' + REPO + '/releases/latest';
const UA = 'vpn-skill-bootstrap/0.1 (local-skill; +https://github.com/MetaCubeX/mihomo)';
const PROBE_TIMEOUT_MS = 8000;        // §3.1：每通道 HEAD 探活 8s 超时
const META_TIMEOUT_MS = 12000;
const DOWNLOAD_IDLE_MS = 60000;       // 下载阶段：单次数据停滞上限
const MAX_BODY = 300 * 1024 * 1024;   // 响应体上限（防异常超大响应）

function sha256(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

// ---------- HTTP 请求核心：超时/重定向跟随/7890 CONNECT 隧道/响应聚合 ----------

// 通道③隧道：经 127.0.0.1:7890 的 CONNECT 建立到目标的 TLS 连接（仅使用其代理端口，R3 合规：
// 禁杀/占/读写 FlClash，「使用」不在禁止列；一次性行为且不可用时通道池照常闭环）
function tunnelAgent(proxyPort) {
  return new https.Agent({
    keepAlive: false,
    createConnection: (options, cb) => {
      let done = false;
      const finish = (err, sock) => { if (done) return; done = true; cb(err, sock); };
      const req = http.request({
        host: '127.0.0.1', port: proxyPort, method: 'CONNECT',
        path: options.host + ':' + (options.port || 443),
        timeout: PROBE_TIMEOUT_MS,
      });
      req.once('connect', (res, socket) => {
        if (res.statusCode !== 200) { socket.destroy(); finish(new Error('CONNECT ' + res.statusCode)); return; }
        const tlsSock = tls.connect({ socket, servername: options.host }, () => finish(null, tlsSock));
        tlsSock.once('error', e => finish(e, null));
      });
      req.once('timeout', () => req.destroy(new Error('tunnel connect timeout')));
      req.once('error', e => finish(e, null));
      req.end();
    },
  });
}

// 统一请求器。opts: {method, headers, timeoutMs(socket 空闲超时), maxRedirects, agent}
// 成功 resolve {status, headers, body:Buffer}；失败 reject（调用方 catch 降级）
function requestUrl(url, opts) {
  const o = opts || {};
  return new Promise((resolve, reject) => {
    const hop = (u, depth) => {
      let pu;
      try { pu = new URL(u); } catch (e) { return reject(new Error('bad url: ' + u)); }
      const req = (pu.protocol === 'https:' ? https : http).request({
        hostname: pu.hostname,
        port: pu.port || (pu.protocol === 'https:' ? 443 : 80),
        path: pu.pathname + pu.search,
        method: o.method || 'GET',
        headers: Object.assign({ 'User-Agent': UA }, o.headers || {}),
        timeout: o.timeoutMs || PROBE_TIMEOUT_MS,
        agent: o.agent || undefined,
      }, res => {
        // 重定向跟随（下载 github release 会经 302 到 objects 域）
        const loc = res.headers.location;
        if ([301, 302, 303, 307, 308].includes(res.statusCode) && loc && depth < (o.maxRedirects || 0)) {
          res.resume();
          return hop(new URL(loc, u).toString(), depth + 1);
        }
        const chunks = [];
        let size = 0;
        res.on('data', c => {
          size += c.length;
          if (size > MAX_BODY) { req.destroy(new Error('response exceeds size limit')); return; }
          chunks.push(c);
        });
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
        res.on('error', e => reject(e));
      });
      req.on('timeout', () => req.destroy(new Error('timeout')));
      req.on('error', e => reject(e));
      req.end();
    };
    hop(url, 0);
  });
}

// ---------- 通道池 ----------

// ①直连 ②gh-proxy.com 前缀（不依赖 FlClash，构成完整冷启动链路）③7890 借道（TCP 探测可用才入池，仅加速）
async function buildChannels(lines) {
  const channels = [
    { name: 'direct', wrap: u => u, agent: null },
    { name: 'gh-proxy', wrap: u => 'https://gh-proxy.com/' + u, agent: null },
  ];
  const has7890 = await util.probeTcpPort(7890, 1500);
  if (has7890) {
    channels.push({ name: 'local-7890', wrap: u => u, agent: tunnelAgent(7890) });
    lines.push('Channel pool: direct -> gh-proxy -> local-7890 (proxy port 7890 detected)');
  } else {
    lines.push('Channel pool: direct -> gh-proxy (no local proxy on 7890)');
  }
  return channels;
}

// 通道探活（§3.1：HEAD release 页，2xx/3xx 即活）
async function probeChannel(ch, lines) {
  const probeUrl = ch.name === 'gh-proxy' ? ch.wrap(RELEASE_PAGE_URL) : RELEASE_PAGE_URL;
  const r = await requestUrl(probeUrl, { method: 'HEAD', timeoutMs: PROBE_TIMEOUT_MS, agent: ch.agent }).catch(() => null);
  const ok = !!(r && r.status >= 200 && r.status < 400);
  lines.push('Channel [' + ch.name + ']: probe ' + (ok ? 'ok (' + r.status + ')' : 'failed') + (ok ? '' : ' -- skipping'));
  return ok;
}

// 通道全链执行：探活 → 元数据 → 选资产 → 下载。返回 {tag, zipBuf, assetUrl} 或 null（失败/降级）
async function tryChannel(ch, lines) {
  if (!(await probeChannel(ch, lines))) return null;
  // 元数据：/releases/latest 端点本身排除 prerelease（alpha），返回最新稳定版
  let meta = null;
  try {
    const mr = await requestUrl(ch.wrap(API_LATEST), {
      timeoutMs: META_TIMEOUT_MS, agent: ch.agent,
      headers: { Accept: 'application/vnd.github+json' },
    });
    if (mr && mr.status === 200) meta = JSON.parse(mr.body.toString('utf8'));
  } catch (e) { meta = null; }
  if (!meta || !meta.tag_name) {
    lines.push('Channel [' + ch.name + ']: metadata fetch failed -- skipping');
    return null;
  }
  const tag = meta.tag_name;
  // 资产选择：精确名 mihomo-windows-amd64-<tag>.zip（精确匹配天然排除 compatible/go*/v1-v3/arm64 变体与源码包）
  const want = 'mihomo-windows-amd64-' + tag + '.zip';
  const asset = (meta.assets || []).find(a => a && a.name === want);
  if (!asset) {
    lines.push('Channel [' + ch.name + ']: asset not found: ' + want);
    return null;
  }
  // 下载（跟随重定向；响应头超时 8s，下载中数据停滞上限 60s）
  let dl = null;
  try {
    dl = await requestUrl(ch.wrap(asset.browser_download_url), {
      timeoutMs: DOWNLOAD_IDLE_MS, maxRedirects: 6, agent: ch.agent,
    });
  } catch (e) {
    lines.push('Channel [' + ch.name + ']: download failed (' + e.message + ')');
    return null;
  }
  if (!dl || dl.status !== 200) {
    lines.push('Channel [' + ch.name + ']: download bad status ' + (dl ? dl.status : 'none'));
    return null;
  }
  lines.push('Channel [' + ch.name + ']: downloaded ' + want + ' (' + dl.body.length + ' bytes)');
  return { tag, zipBuf: dl.body, assetUrl: asset.browser_download_url, channelName: ch.name };
}

// ---------- 手写 zip 单条目提取（零 npm 依赖；EOCD → central directory → local header → inflateRaw） ----------

function extractZipEntry(buf, nameRe) {
  // 1. EOCD：从尾部向前扫签名 0x06054b50（注释区 ≤65535）
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 22 - 65535); i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error('zip: EOCD signature not found');
  const count = buf.readUInt16LE(eocd + 10);
  let off = buf.readUInt32LE(eocd + 16);
  if (off === 0xFFFFFFFF) throw new Error('zip: ZIP64 not supported');
  // 2. central directory 遍历
  for (let i = 0; i < count; i++) {
    if (off + 46 > buf.length || buf.readUInt32LE(off) !== 0x02014b50) throw new Error('zip: bad central directory');
    const method = buf.readUInt16LE(off + 10);
    const compSize = buf.readUInt32LE(off + 20);
    const nameLen = buf.readUInt16LE(off + 28);
    const extraLen = buf.readUInt16LE(off + 30);
    const cmtLen = buf.readUInt16LE(off + 32);
    const lho = buf.readUInt32LE(off + 42);
    const name = buf.slice(off + 46, off + 46 + nameLen).toString('utf8');
    if (nameRe.test(name)) {
      // 3. local file header：以自身字段定位数据区（local 与 central 的 extra 长度可能不同）
      if (buf.readUInt32LE(lho) !== 0x04034b50) throw new Error('zip: bad local header');
      const lnLen = buf.readUInt16LE(lho + 26);
      const leLen = buf.readUInt16LE(lho + 28);
      const dataStart = lho + 30 + lnLen + leLen;
      const data = buf.slice(dataStart, dataStart + compSize);
      if (method === 0) return Buffer.from(data);                    // store
      if (method === 8) return zlib.inflateRawSync(data);            // deflate
      throw new Error('zip: unsupported compression method ' + method);
    }
    off += 46 + nameLen + extraLen + cmtLen;
  }
  return null;
}

// r1 可沉淀知识#1 应用：内核就位前独立进程跑 -v——确认标准 mihomo CLI 语义（FlClashCore 把 argv 当文件路径的教训）
function verifyCliSemantics(exePath) {
  return new Promise(resolve => {
    const p = spawn(exePath, ['-v'], { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    let out = '';
    const t = setTimeout(() => { try { p.kill(); } catch (e) { /* noop */ } }, 10000);
    p.stdout.setEncoding('utf8'); p.stdout.on('data', c => { out += c; });
    p.stderr.setEncoding('utf8'); p.stderr.on('data', c => { out += c; });
    p.on('error', () => { clearTimeout(t); resolve(false); });
    p.on('close', code => { clearTimeout(t); resolve(code === 0 && /mihomo|meta|version/i.test(out)); });
  });
}

// ---------- latest 版本查询（§3.1 版本管理/§13：doctor 比对官方 latest 提示升级——M2 导出复用） ----------
// 走本模块通道池逐通道取 /releases/latest 的 tag_name（不做通道探活，元数据请求本身即探活）；
// 全通道失败返回 null，调用方降级为本地比对+警告（不阻塞诊断）
async function fetchLatestTag() {
  const notes = [];
  const channels = await buildChannels(notes);
  for (const ch of channels) {
    try {
      const mr = await requestUrl(ch.wrap(API_LATEST), {
        timeoutMs: META_TIMEOUT_MS, agent: ch.agent,
        headers: { Accept: 'application/vnd.github+json' },
      });
      if (mr && mr.status === 200) {
        const j = JSON.parse(mr.body.toString('utf8'));
        if (j && typeof j.tag_name === 'string') return { tag: j.tag_name, channel: ch.name, notes };
      }
    } catch (e) { /* 下一通道 */ }
  }
  return null;
}

// ---------- 主流程 ----------

async function run() {
  const root = util.skillRoot();
  const P = util.paths();
  const lines = [];
  lines.push('Kernel bootstrap: mihomo windows-amd64 stable release');

  // 幂等跳过（§4：已有且 sha256 校验通过 → 跳过；删除 kernel.json 或 bin 可强制重装）
  if (fs.existsSync(P.kernelExe) && fs.existsSync(P.kernelJson)) {
    let kj = null;
    try { kj = JSON.parse(fs.readFileSync(P.kernelJson, 'utf8')); } catch (e) { kj = null; }
    const cur = sha256(fs.readFileSync(P.kernelExe));
    if (kj && kj.sha256 === cur) {
      lines.push('Kernel already installed and sha256 verified -- skip');
      return { lines, json: { kernel_version: kj.version, sha256: kj.sha256, channel: kj.channel, skipped: true }, rc: 0 };
    }
    lines.push('Kernel sha256 mismatch with kernel.json -- reinstalling');
  }
  fs.mkdirSync(P.bin, { recursive: true });

  // 通道池顺序尝试（§3.1）
  const channels = await buildChannels(lines);
  let got = null;
  for (const ch of channels) {
    got = await tryChannel(ch, lines);
    if (got) break;
  }
  if (!got) {
    // fail_to_human（§3.1 风险缓解：不静默重试）
    lines.push('All channels failed.');
    lines.push('FAIL_TO_HUMAN: manually download mihomo windows-amd64 zip, extract mihomo.exe into');
    lines.push('  <skill>/bin/mihomo.exe  then rerun bootstrap to record kernel.json');
    return { lines, json: { error: 'all-channels-failed', channels: channels.map(c => c.name) }, rc: 1 };
  }
  const shaZip1 = sha256(got.zipBuf);

  // [VERIFY 实测] mihomo release 无 checksums 资产 → 双通道交叉校验：另一活通道重下 zip 比对 SHA256
  let crossOk = false;
  let crossNote = '';
  for (const ch of channels) {
    if (ch.name === got.channelName) continue; // 交叉校验必须走另一条独立通道
    try {
      const r2 = await requestUrl(ch.wrap(got.assetUrl), {
        timeoutMs: DOWNLOAD_IDLE_MS, maxRedirects: 6, agent: ch.agent,
      });
      if (r2 && r2.status === 200 && sha256(r2.body) === shaZip1) {
        crossOk = true;
        crossNote = 'cross-channel sha256 match via ' + ch.name;
        break;
      }
    } catch (e) { /* 通道不可用：尝试下一个 */ }
  }

  // 解压：zip 内定位内核 exe。[VERIFY 实测] 条目名为 mihomo-windows-amd64.exe（带平台前缀），
  // 非裸 mihomo.exe——先试裸名，回退平台前缀形态；兼容单层目录嵌套布局
  let exeBuf = null;
  try {
    exeBuf = extractZipEntry(got.zipBuf, /(^|\/)mihomo\.exe$/i)
      || extractZipEntry(got.zipBuf, /(^|\/)mihomo[\w.-]*-windows-amd64\.exe$/i)
      || extractZipEntry(got.zipBuf, /(^|\/)mihomo[\w.-]*\.exe$/i);
  } catch (e) {
    lines.push('Zip extract failed: ' + e.message);
    return { lines, json: { error: 'zip-extract-failed' }, rc: 1 };
  }
  if (!exeBuf) {
    lines.push('Zip layout unexpected: mihomo.exe entry not found');
    return { lines, json: { error: 'zip-entry-missing' }, rc: 1 };
  }
  const shaExe = sha256(exeBuf);

  // 写 .new → -v 验证 → 轮转 .prev → 落位（§3.1；运行中的内核文件被锁 → 提示先 stop，§2 时序④）
  const newPath = path.join(P.bin, 'mihomo.exe.new');
  fs.writeFileSync(newPath, exeBuf);
  const cliOk = await verifyCliSemantics(newPath);
  if (!cliOk) {
    try { fs.unlinkSync(newPath); } catch (e) { /* noop */ }
    lines.push('Downloaded binary failed -v CLI semantics check -- aborted (binary left uninstalled)');
    return { lines, json: { error: 'cli-verify-failed', sha256: shaExe }, rc: 1 };
  }
  // ---- 替换链（M3，§3.1「升级=bootstrap 重跑：自动 stop→替换→恢复原状态」+§2 时序④文件锁） ----
  // 旧 exe 被锁=内核运行中 → 自动停链（复用 core.cmdStop：PID+路径双校验+互守+终态，
  // R3 不变量不变）→ 轮转重试 → 落位 → kernel.json → **按停前状态自动恢复运行**；
  // 任何步骤失败 → .prev 回滚尝试 + fail_to_human rc=1（不静默、不留无内核态）
  const core = require('./core'); // 惰性 require：core 不依赖 bootstrap（无循环依赖）
  const prevPath = path.join(P.bin, 'mihomo.exe.prev');
  let wasRunning = false;
  let prevVersion = null;
  if (fs.existsSync(P.kernelJson)) {
    try { prevVersion = JSON.parse(fs.readFileSync(P.kernelJson, 'utf8')).version || null; } catch (e) { prevVersion = null; }
  }

  // 回滚：.prev → exe 恢复旧内核；wasRunning 时尽力自动重启（升级中止但系统回到停前形态）
  async function rollbackAfterFailure(reason) {
    lines.push('Upgrade failed at [' + reason + '] -- attempting rollback to previous kernel');
    let restored = false;
    try {
      fs.renameSync(prevPath, P.kernelExe);
      restored = true;
      lines.push('Rollback ok: previous kernel binary restored');
    } catch (e) {
      lines.push('Rollback failed: ' + (e && e.message ? e.message : 'unknown') + ' -- FAIL_TO_HUMAN');
    }
    try { fs.unlinkSync(newPath); } catch (e) { /* .new 残留无害（下次重装覆盖） */ }
    if (wasRunning && restored) {
      const sr = await core.cmdStart();
      for (const l of sr.lines) lines.push(l);
      lines.push(sr.rc === 0 ? 'Previous kernel restarted (upgrade aborted)'
        : 'Restart failed -- run: node scripts/vpn.js start');
    } else if (wasRunning) {
      lines.push('Kernel was stopped and rollback incomplete -- restore bin/mihomo.exe manually, then run start');
    }
    return { lines, json: { error: 'upgrade-failed-' + reason, rolled_back: restored }, rc: 1 };
  }

  if (fs.existsSync(P.kernelExe)) {
    // M3 前置：内核在跑则**主动**自动停链（readRuntime+pidAlive 探测，任务书规定的判据）。
    // 实测教训：Windows 允许 rename 运行中的 exe（文件锁不构成可靠运行判据）——若被动等
    // rename 失败才停，会留下「进程运行旧二进制（已改名 .prev）+ kernel.json 记录新版本」
    // 的漂移形态；主动停链保证升级原子性与恢复路径触发
    const rtBefore = util.readRuntime(root);
    if ((rtBefore.state === 'running' || rtBefore.state === 'degraded') &&
        rtBefore.mihomo_pid && core.pidAlive(rtBefore.mihomo_pid)) {
      wasRunning = true;
      lines.push('Kernel running (pid ' + rtBefore.mihomo_pid + ') -- auto-stopping for upgrade');
      const stopRes = await core.cmdStop();
      for (const l of stopRes.lines) lines.push(l);
    }
    try {
      fs.renameSync(P.kernelExe, prevPath);
    } catch (e) {
      // 停链后仍无法轮转（外部进程锁定，如 AV）：删 .new、尽力恢复运行、fail_to_human
      try { fs.unlinkSync(newPath); } catch (e3) { /* noop */ }
      lines.push('FAIL_TO_HUMAN: cannot rotate bin/mihomo.exe (locked by another process?)');
      if (wasRunning) {
        const sr = await core.cmdStart();
        for (const l of sr.lines) lines.push(l);
        if (sr.rc !== 0) lines.push('Restart failed -- run: node scripts/vpn.js start');
      }
      return { lines, json: { error: 'rotate-blocked' }, rc: 1 };
    }
  }
  try {
    fs.renameSync(newPath, P.kernelExe);
  } catch (e) {
    return await rollbackAfterFailure('place-new-kernel');
  }

  const kernelJson = {
    version: got.tag,
    sha256: shaExe,
    zip_sha256: shaZip1,           // 审计：zip 包哈希（双通道校验对象）
    channel: got.channelName,
    cross_verified: crossOk,
    date: new Date().toISOString(),
    prev_version: prevVersion,
  };
  try {
    fs.writeFileSync(P.kernelJson, JSON.stringify(kernelJson, null, 2) + '\n', 'utf8');
  } catch (e) {
    return await rollbackAfterFailure('write-kernel-json');
  }

  lines.push('Installed: ' + got.tag + ' sha256=' + shaExe);
  lines.push(crossOk ? crossNote : 'Warning: cross-channel verification unavailable -- single-channel download recorded');

  // 按停前状态自动恢复（M3：原本 running → 新内核自动 restart；失败显式指引，不静默）
  let restoredRunning = 'not-needed';
  if (wasRunning) {
    lines.push('Kernel was running before upgrade -- auto-restarting on new version');
    const sr = await core.cmdStart();
    for (const l of sr.lines) lines.push(l);
    if (sr.rc === 0) restoredRunning = 'restarted';
    else {
      restoredRunning = 'failed';
      lines.push('Auto-restart FAILED -- run: node scripts/vpn.js start');
    }
  }
  return {
    lines,
    json: {
      kernel_version: got.tag, sha256: shaExe, zip_sha256: shaZip1,
      channel: got.channelName, verify: crossOk ? 'cross-channel-sha256' : 'single-channel-unverified',
      cross_verified: crossOk, prev_version: prevVersion,
      restored_running: restoredRunning,
    },
    rc: (!crossOk || restoredRunning === 'failed') ? 2 : 0, // 单通道/恢复失败=成功带警告（§4 退出码 2）
  };
}

module.exports = { run, extractZipEntry, verifyCliSemantics, buildChannels, fetchLatestTag };
