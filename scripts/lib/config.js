/**
 * config.js — mihomo config.yaml 生成器（完整模板，设计 §4.1）
 *
 * 职责：读 user/subscriptions.yaml + user/sources.yaml + 注入参数
 * （试绑定实得端口 / secret 由调用方传入——start 流程负责试绑定，
 * 本模块不做端口探测，与 t1 的 util 试绑定函数解耦）→ 生成完整 config
 * → 原子写 var/config.yaml。
 *
 * 模板要点（§4.1 逐键对照）：
 *  - 双轨 provider：订阅 type:http 直连（不配 proxy 字段——R2 合规论证
 *    见设计 §3.2，不得"优化"成走池代理）；免费源 type:file 指本地缓存
 *  - 单 url-test 组 include-all: true，unified-delay: true（顶层键）、
 *    interval: 300、tolerance: 100
 *  - override 前缀：override.additional-prefix（字段名以 mihomo wiki
 *    proxy-providers override 节为准，已核对：additional-prefix 为官方
 *    文档字段，"Adds a fixed prefix to the node names"）
 *  - 每 provider 自带 health-check（组级 url 不检查 use 引入节点，r2 §3.1 陷阱）
 *
 * R1 静态保证：模板不含 tun / tproxy-port / redir-port / dns /
 * external-controller-pipe / external-doh-server 键（grep 锚）；
 * 生成后再做一次运行时断言双保险。
 */

'use strict';

const fs = require('fs');
const path = require('path');
const yaml = require('../vendor/yaml');
const { readYamlFile, atomicWrite } = require('./providers');

// ── 路径（__dirname 向上定位，禁止绝对路径硬编码） ──
const SKILL_ROOT = path.resolve(__dirname, '..', '..');
const USER_DIR = path.join(SKILL_ROOT, 'user');
const VAR_DIR = path.join(SKILL_ROOT, 'var');
const SUBSCRIPTIONS_FILE = path.join(USER_DIR, 'subscriptions.yaml');
const SOURCES_FILE = path.join(USER_DIR, 'sources.yaml');
const CONFIG_FILE = path.join(VAR_DIR, 'config.yaml');

// ── 模板常量（§4.1） ──
const HEALTH_CHECK = {
  enable: true,
  url: 'https://www.gstatic.com/generate_204',
  interval: 300,
  timeout: 5000,
  'expected-status': 204,
};
const SUB_INTERVAL = 86400;        // 订阅更新 24h（r2 §4.1 Verge 惯例）
const GROUP_INTERVAL = 300;        // 组测速周期（官方示例值）
const GROUP_TOLERANCE = 100;       // url-test 容差 ms（惯例 50-200 取中；
                                   // 字段存在性已核 mihomo wiki url-test 专页）
const OVERRIDE_PREFIX_SUB = '[sub]';        // override 前缀参数位（wiki 字段 additional-prefix）
const OVERRIDE_PREFIX_FREE = '[free:{name}]';

// R1 禁键（grep 锚全集；运行时断言用）
const FORBIDDEN_KEYS = [
  'tun',
  'tproxy-port',
  'redir-port',
  'dns',
  'external-controller-pipe',
  'external-doh-server',
];

// R3 防御：FlClash 保留端口（候选生成器在调用方，此处挡第二道）
const FORBIDDEN_PORTS = new Set([7890, 9090]);

/**
 * provider/组名净化：只留字母数字下划线连字符
 */
function sanitizeName(s) {
  return String(s).replace(/[^\w-]/g, '_');
}

/**
 * 端口参数校验：整数 + 非特权 + 非 FlClash 保留段
 */
function assertPort(label, p) {
  if (!Number.isInteger(p) || p < 1024 || p > 65535) {
    throw new Error(label + ' invalid: ' + p);
  }
  if (FORBIDDEN_PORTS.has(p)) {
    throw new Error(label + ' ' + p + ' is forbidden (FlClash reserved port)');
  }
}

/**
 * 收集双轨 provider 清单（不生成 config，供 update 热更名单复用）。
 * 返回 [{ name, kind: 'sub'|'free' }]。
 */
function listProviderEntries() {
  const entries = [];
  const subsDoc = readYamlFile(SUBSCRIPTIONS_FILE);
  if (subsDoc && Array.isArray(subsDoc.subscriptions)) {
    for (const s of subsDoc.subscriptions) {
      if (!s || typeof s !== 'object' || !s.name || !s.url) continue;
      if (s.enabled === false) continue;
      entries.push({ name: 'sub-' + sanitizeName(s.name), kind: 'sub' });
    }
  }
  const srcDoc = readYamlFile(SOURCES_FILE);
  if (srcDoc && Array.isArray(srcDoc.sources)) {
    for (const s of srcDoc.sources) {
      if (!s || typeof s !== 'object' || !s.name) continue;
      entries.push({ name: 'free-' + sanitizeName(s.name), kind: 'free' });
    }
  }
  return entries;
}

/**
 * 构造完整 config 对象（§4.1 模板逐键）。
 * @param {object} params { mixedPort, apiPort, secret }（试绑定实得端口与随机 secret）
 * @returns {{ config: object, providerEntries: Array }}
 */
function buildConfig(params) {
  const mixedPort = params && params.mixedPort;
  const apiPort = params && params.apiPort;
  const secret = params && params.secret;
  assertPort('mixed-port', mixedPort);
  assertPort('api-port', apiPort);
  if (typeof secret !== 'string' || !/^[0-9a-f]{16,}$/i.test(secret)) {
    throw new Error('secret must be a hex string (>=16 chars)');
  }

  const proxyProviders = {};
  const providerEntries = [];
  const subsDoc = readYamlFile(SUBSCRIPTIONS_FILE);
  const srcDoc = readYamlFile(SOURCES_FILE);

  // 轨道一：机场订阅（type:http 直连，不含 proxy 字段——R2）
  if (subsDoc && Array.isArray(subsDoc.subscriptions)) {
    for (const s of subsDoc.subscriptions) {
      if (!s || typeof s !== 'object' || !s.name || !s.url) continue;
      if (s.enabled === false) continue;
      const pname = 'sub-' + sanitizeName(s.name);
      proxyProviders[pname] = {
        type: 'http',
        url: s.url,
        interval: SUB_INTERVAL,
        path: 'providers/' + pname + '.yaml', // 相对 HomeDir=var/（SAFE_PATHS 合规）
        override: { 'additional-prefix': OVERRIDE_PREFIX_SUB },
        'health-check': Object.assign({}, HEALTH_CHECK),
      };
      providerEntries.push({ name: pname, kind: 'sub' });
    }
  }

  // 轨道二：免费源（type:file 指本地缓存，通道冗余由 Node 层 providers.js 承载）
  if (srcDoc && Array.isArray(srcDoc.sources)) {
    for (const s of srcDoc.sources) {
      if (!s || typeof s !== 'object' || !s.name) continue;
      const pname = 'free-' + sanitizeName(s.name);
      proxyProviders[pname] = {
        type: 'file',
        path: 'providers/' + pname + '.yaml',
        override: {
          'additional-prefix': OVERRIDE_PREFIX_FREE.replace('{name}', sanitizeName(s.name)),
        },
        'health-check': Object.assign({}, HEALTH_CHECK),
      };
      providerEntries.push({ name: pname, kind: 'free' });
    }
  }

  const config = {
    'mixed-port': mixedPort,
    'allow-lan': false,
    'mode': 'rule',
    'unified-delay': true, // 跨协议公平比较必开（r2 §3.1）
    'log-level': 'info',
    'external-controller': '127.0.0.1:' + apiPort, // 仅 bind 本机回环
    'secret': secret,
    'proxy-providers': proxyProviders,
    'proxy-groups': [
      {
        name: 'POOL',
        type: 'url-test',
        'include-all': true, // 平权混池【需求#1：不偏爱订阅】
        url: 'https://www.gstatic.com/generate_204',
        interval: GROUP_INTERVAL,
        tolerance: GROUP_TOLERANCE,
      },
    ],
    rules: ['MATCH,POOL'],
  };
  return { config, providerEntries };
}

/**
 * R1 运行时断言：生成文本顶层不含禁键（模板字面已保证，双保险）。
 */
function assertNoForbiddenKeys(text) {
  for (const k of FORBIDDEN_KEYS) {
    const re = new RegExp('^' + k.replace(/[-]/g, '\\-') + ':', 'm');
    if (re.test(text)) {
      throw new Error('R1 violation: forbidden key "' + k + '" in generated config');
    }
  }
}

/**
 * 生成并原子写 var/config.yaml。
 * @param {object} params { mixedPort, apiPort, secret }
 * @returns {{ configPath: string, providerCount: number, providerEntries: Array }}
 */
function generate(params) {
  const { config, providerEntries } = buildConfig(params);
  const text = yaml.stringify(config);
  assertNoForbiddenKeys(text);
  fs.mkdirSync(path.join(VAR_DIR, 'providers'), { recursive: true });
  atomicWrite(CONFIG_FILE, text);
  return {
    configPath: CONFIG_FILE,
    providerCount: providerEntries.length,
    providerEntries,
  };
}

module.exports = {
  generate,
  buildConfig,
  listProviderEntries,
  paths: {
    skillRoot: SKILL_ROOT,
    subscriptionsFile: SUBSCRIPTIONS_FILE,
    sourcesFile: SOURCES_FILE,
    configFile: CONFIG_FILE,
  },
};
