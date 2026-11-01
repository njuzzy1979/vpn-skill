/**
 * export-top.js — 延迟 Top N 节点导出（t7；用户需求：每次更新测速后生成延迟前 100 名节点文件）
 *
 * 数据链（只读消费现有拉取链的产品，不改 bootstrap/core/config/providers）：
 *  ① GET /providers/proxies（lib/api.js getProviderAll；t7 实测修正：/proxies 的
 *     proxies map 只含组与内建策略、不展开 provider 节点，每节点 history 延迟只在
 *     /providers/proxies 端点）→ 只取免费源 provider（free-*）下全部节点 →
 *     **排除订阅（t7 增补：sub-* provider 整体排除 + [sub] 名字前缀防御性双挡——
 *     用户已有完整订阅，仅导出免费节点；无前缀节点按免费处理并计数）** →
 *     每节点取 history 最近一次非零 delay → 升序取前 N
 *  ② 节点完整对象（API 端点不含 server/port 凭据字段）从 var/providers/free-*.yaml
 *     缓存匹配——名字匹配陷阱：API 侧名字带 override 前缀（config.js
 *     additional-prefix：`[free:源名]xxx`），provider 缓存文件内是原始名——剥前缀后
 *     按源名路由到 free-<源名>.yaml；无前缀节点顺序遍历全部 free 源索引
 *  ③ 导出对象 name 改用带前缀名（保留来源信息 + 防跨源重名冲突）
 *  ④ yaml 原子写 exports/top100.yaml（providers.atomicWrite，tmp+rename）
 *
 * 输出契约（R2）：本模块为纯函数库（不 console 输出，打印由 cmd 层负责）；调用方
 * 只允许输出统计量与路径，绝不打印节点凭据/服务器地址。导出位置演进：初版 var/providers
 * （gitignore 区）→ 2026-11-01 用户二次拍板「top100 免费节点进库」→ 改 exports/（默认
 * 进 git 仓库）。隐私论证：文件仅含免费节点凭据（公开聚合源产物，可公开）；订阅节点经
 * 四重防御结构上不可达本文件（guard_t7 实证）——若未来放宽仅免费约束，必须回迁 gitignore 区。
 *
 * 返回 null = 内核未运行（runtime 缺失或 /proxies 无应答）——调用方区分提示；
 * 其他异常（缓存读坏/写失败等）抛出，由调用方 try/catch。
 */

'use strict';

const fs = require('fs');
const path = require('path');

const util = require('./util');
const api = require('./api');
const providers = require('./providers'); // readYamlFile / atomicWrite（域内共享工具）
const yaml = require('../vendor/yaml');

const TOP_DEFAULT = 100;
const EXPORT_FILENAME = 'top100.yaml'; // 固定名覆盖（用户拍板：固定名；位置演进见头部注释，现=exports/ 进库）
const EXPORT_REL = 'exports/' + EXPORT_FILENAME; // 输出/日志用相对路径（ASCII 安全）；exports/ 不在 gitignore=随库分发

// 组/内建策略类型集合（/proxies 返回混含 POOL 等组对象与 DIRECT/REJECT 内建策略，
// 均非真实代理节点，按 type 排除；判据实测记录见 t7_impl.md）
const NON_PROXY_TYPES = new Set([
  'Selector', 'URLTest', 'Fallback', 'LoadBalance', 'Relay',
  'Direct', 'Reject', 'Compatible', 'Pass', 'RejectDrop',
]);

// override 前缀解析（与 config.js OVERRIDE_PREFIX_SUB / OVERRIDE_PREFIX_FREE 对偶）
const RE_FREE_PREFIX = /^\[free:([^\]]+)\]/;
const RE_SUB_PREFIX = /^\[sub\]/;

/**
 * 剥 API 名字的 override 前缀。
 * @returns {{kind:'free'|'sub', src:string|null, base:string}|null} null=无已知前缀
 */
function parseApiName(apiName) {
  const m = RE_FREE_PREFIX.exec(apiName);
  if (m) return { kind: 'free', src: m[1], base: apiName.slice(m[0].length) };
  if (RE_SUB_PREFIX.test(apiName)) return { kind: 'sub', src: null, base: apiName.slice('[sub]'.length) };
  return null;
}

/**
 * 从 /providers/proxies 响应收集免费源候选节点。
 * 判据（t7 实测记录）：provider 名 free-* = 免费源缓存（File vehicleType），节点 type
 * 全为具体协议名（Shadowsocks/Vless/...）；sub-* = 订阅（HTTP）整体排除；default
 * （Compatible，含 Direct/Reject/URLTest 内建与组）不入 free-* 名单天然排除。
 * NON_PROXY_TYPES 作防御性二道过滤（理论上 free provider 下不出现，实测零命中）。
 */
function collectFreeCandidates(pdoc) {
  const providersMap = (pdoc && pdoc.providers) || {};
  const out = [];
  let excludedSub = 0;
  for (const provName of Object.keys(providersMap)) {
    const prov = providersMap[provName] || {};
    const list = Array.isArray(prov.proxies) ? prov.proxies : [];
    if (provName.startsWith('sub-')) {
      excludedSub += list.length; // t7 增补：订阅 provider 整体排除（用户已有完整订阅）
      continue;
    }
    if (!provName.startsWith('free-')) continue; // default 等非源 provider
    for (const p of list) {
      if (!p || typeof p !== 'object' || typeof p.name !== 'string') continue;
      if (NON_PROXY_TYPES.has(p.type)) continue;            // 防御：组/内建类型混入
      if (RE_SUB_PREFIX.test(p.name)) continue;             // 防御：[sub] 前缀双挡
      out.push(p);
    }
  }
  return { nodes: out, excludedSub };
}

/**
 * 取节点 history 中最近一次非零 delay（毫秒）。从数组末位向前找第一个 delay>0；
 * 无 history / 全零 / 超时标记 0 → 返回 0（调用方按无有效延迟排除）。
 */
function latestDelay(p) {
  const h = Array.isArray(p.history) ? p.history : [];
  for (let i = h.length - 1; i >= 0; i--) {
    const d = h[i] && h[i].delay;
    if (typeof d === 'number' && d > 0) return d;
  }
  return 0;
}

/**
 * 加载 var/providers/ 免费源缓存并建名字索引（源名 → (原始名 → 完整节点对象)）。
 * 只认 free-<name>.yaml 命名（自动排除 top100.yaml 导出件、sub-*.yaml 与 .tmp 残留——
 * 仅导出免费节点，订阅缓存不读）。按源名分组索引（[free:src] 精确路由防跨源重名错配）。
 */
function loadProviderIndexes() {
  const dir = util.paths().varProviders;
  const idx = { free: new Map() };
  let files = [];
  try { files = fs.readdirSync(dir); } catch (e) { return idx; }
  for (const f of files) {
    if (f.endsWith('.tmp') || f.startsWith('.')) continue;
    const m = /^free-(.+)\.yaml$/.exec(f);
    if (!m) continue; // sub-*.yaml / top100.yaml 等非免费源缓存文件
    const doc = providers.readYamlFile(path.join(dir, f));
    if (!doc || !Array.isArray(doc.proxies)) continue;
    const byName = new Map();
    for (const px of doc.proxies) {
      if (px && typeof px === 'object' && typeof px.name === 'string') byName.set(px.name, px);
    }
    idx.free.set(m[1], byName);
  }
  return idx;
}

/**
 * 按剥前缀结果在缓存索引中找完整节点对象。free 路由到对应源文件；
 * 无前缀节点按免费处理（顺序遍历全部 free 源索引取首个命中）；未命中返回 null。
 */
function findProxyObject(idx, parsed, rawName) {
  if (parsed && parsed.kind === 'free') {
    const byName = idx.free.get(parsed.src);
    return (byName && byName.get(parsed.base)) || null;
  }
  if (parsed && parsed.kind === 'sub') return null; // 防御：候选阶段已排除 sub（不导出订阅节点）
  const base = parsed ? parsed.base : rawName;
  for (const byName of idx.free.values()) {
    if (byName.has(base)) return byName.get(base);
  }
  return null;
}

/**
 * 延迟 Top N 导出。
 * @param {object} [opts] { top=100, apiPort, secret }（apiPort/secret 缺省时从 runtime.json 读取）
 * @returns {Promise<{exported:number,total_candidates:number,file:string}|null>}
 *          null=内核未运行；{exported,total_candidates,file} 为统计（file=相对路径）
 * @throws 顶层参数非法 / yaml 写失败（调用方 try/catch，不影响主流程退出码）
 */
async function exportTop(opts) {
  const o = opts || {};
  const top = (o.top === undefined) ? TOP_DEFAULT : o.top;
  if (!Number.isInteger(top) || top < 1) {
    throw new Error('invalid top: ' + top + ' (must be integer >= 1)');
  }

  // ① runtime 补参 + 全量 provider 节点（/providers/proxies 无应答 → null：内核未运行语义）
  let apiPort = o.apiPort;
  let secret = o.secret;
  if (!apiPort || !secret) {
    const rt = util.readRuntime(util.skillRoot());
    apiPort = apiPort || rt.api_port;
    secret = secret || rt.secret;
  }
  if (!apiPort || !secret) return null;
  const pdoc = await api.getProviderAll(apiPort, secret);
  if (!pdoc) return null;

  // ② 免费源候选（sub-* provider 整体排除）→ 每节点最近一次非零延迟 → 升序取前 N
  const free = collectFreeCandidates(pdoc);
  const candidates = [];
  let unprefixed = 0;
  for (const p of free.nodes) {
    const parsed = parseApiName(p.name);
    if (!parsed) unprefixed++; // 理论不出现（override 恒加前缀，实测 free-zhuhaiuk 33/33 带）
    const d = latestDelay(p);
    if (d > 0) candidates.push({ name: p.name, delay: d, parsed });
  }
  candidates.sort((a, b) => a.delay - b.delay);
  const picked = candidates.slice(0, top);

  // ③ 缓存索引匹配完整对象（剥前缀 → 路由 → name 改用带前缀名）
  const idx = loadProviderIndexes();
  const outProxies = [];
  for (const c of picked) {
    const obj = findProxyObject(idx, c.parsed, c.name);
    if (obj) outProxies.push(Object.assign({}, obj, { name: c.name }));
  }

  // ④ 原子写（文件头两行注释：生成时间 + 中文口径行；凭据仅存于 proxies 节内，var/ 已 gitignore）
  const file = path.join(util.skillRoot(), 'exports', EXPORT_FILENAME);
  fs.mkdirSync(path.dirname(file), { recursive: true }); // exports/ 目录自建（首次导出前进程可能未跑过 start）
  const header =
    '# 生成时间: ' + new Date().toISOString() + '\n' +
    '# 口径: 仅免费节点（订阅节点不重复导出），按最近一次测得延迟（毫秒）升序，前 ' + outProxies.length + ' / 免费候选共 ' + candidates.length + ' 个\n';
  try {
    fs.mkdirSync(path.dirname(file), { recursive: true });
  } catch (e) { /* 目录已存在等场景由 atomicWrite 兜底 */ }
  providers.atomicWrite(file, header + yaml.stringify({ proxies: outProxies }) + '\n');

  return {
    exported: outProxies.length,
    total_candidates: candidates.length,
    file: EXPORT_REL,
    included: 'free-only',
    excluded_sub: free.excludedSub,
    unprefixed,
  };
}

module.exports = { exportTop, EXPORT_FILENAME, EXPORT_REL };
