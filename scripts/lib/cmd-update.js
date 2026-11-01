/**
 * cmd-update.js — update 子命令 handler（设计 §4 / §13）
 *
 * 行为：providers.refreshAll() 重拉免费源缓存 → config.generate 重新生成 var/config.yaml
 * （M5：增删源后新 provider 集合至少下次 start/restart 生效；mihomo 运行实例不重读
 * config 文件，故运行中新增的 provider 名 PUT 返回 404 → 输出「需 restart 生效」提示）
 * → 若内核在跑（GET /version 探测；api_port/secret 读 var/runtime.json，util.readRuntime
 * 容错）→ PUT /providers/proxies/:name 逐个热更（免费源 + 订阅 provider 全量）。
 *
 * t3 联调收口：原内置最小 http 客户端已切换为 lib/api.js 统一客户端
 * （127.0.0.1 回环 + Bearer 认证）。
 *
 * 输出协议：英文 ASCII 行 + ===JSON=== + 单行 JSON。
 * 退出码：0=全成功 / 1=流程失败 / 2=完成但源有失败（警告，含全灭——
 * 空池占位已按设计落盘，属"成功带警告"而非流程失败）。
 *
 * R2：源失败信息只含截断 host（providers.js maskUrl + util.sanitize 已保证）；
 * 本层不再输出任何 URL。
 */

'use strict';

const providers = require('./providers');
const config = require('./config');
const api = require('./api');       // t3 联调收口：内置最小客户端切换为 lib/api.js 统一客户端
const util = require('./util');
const exportTop = require('./export-top').exportTop; // t7：更新+热更后自动导出延迟 Top N

/**
 * 输出协议：英文行 + ===JSON=== + 单行 JSON
 */
function emitResult(lines, obj) {
  for (const l of lines) console.log(l);
  console.log('===JSON===');
  console.log(JSON.stringify(obj));
}

/**
 * 内核存活探测：GET /version 应答视为在跑。
 * runtime.json 缺失/损坏/字段不全 → 直接视为未运行（util.readRuntime 容错返回 {}）。
 */
async function probeKernel() {
  const rt = util.readRuntime(util.skillRoot());
  if (!rt.api_port || !rt.secret) return null;
  const v = await api.getVersion(rt.api_port, rt.secret);
  return v ? rt : null;
}

/**
 * update handler
 * @param {string[]} argv 子命令后的参数数组（当前无参数）
 * @returns {Promise<number>} 退出码
 */
async function handle(argv) {
  // ① 重拉免费源缓存（多通道降级 + 空池占位逻辑在 providers 内）
  let refresh;
  try {
    refresh = await providers.refreshAll();
  } catch (e) {
    emitResult(
      ['error: refresh failed: ' + (e && e.message ? e.message : 'unknown')],
      { sources_ok: 0, sources_failed: 0, providers_updated: 0, error: 'refresh-failed' }
    );
    return 1;
  }

  const lines = [];
  for (const r of refresh.results) {
    if (r.ok) {
      lines.push('source ' + r.name + ': ok via ' + r.channel + ' (' + r.nodes + ' nodes, ' + r.ms + 'ms)');
    } else {
      // 失败明细：通道 + 截断 host + 原因（R2：无 URL 全文）
      const detail = r.attempts.map((a) => a.channel + ': ' + a.error).join('; ');
      lines.push('source ' + r.name + ': FAILED (all channels) [' + detail + ']');
    }
  }

  // ② config 重新生成（M5，§13 源清单演进）：增删源后重生成 var/config.yaml，使新
  // provider 集合至少在下次 start/restart 生效（mihomo 运行实例不重读 config 文件）。
  // 参数取 runtime 现存端口/secret（与当前实例一致）；runtime 无效则跳过并注记
  //（下次 start 由 cmdStart 全新生成，不影响启动正确性）。
  let configRegen = 'skipped';
  const rtCfg = util.readRuntime(util.skillRoot());
  if (rtCfg.proxy_port && rtCfg.api_port && rtCfg.secret) {
    try {
      const gen = config.generate({ mixedPort: rtCfg.proxy_port, apiPort: rtCfg.api_port, secret: rtCfg.secret });
      configRegen = 'regenerated';
      lines.push('Config regenerated: ' + gen.providerCount + ' providers (running kernel keeps old config until restart)');
    } catch (e) {
      configRegen = 'failed';
      lines.push('Warning: config regeneration failed: ' + (e && e.message ? e.message : 'unknown'));
    }
  } else {
    lines.push('Config regeneration skipped (no valid ports/secret in runtime; start will generate)');
  }

  // ③ 内核在跑则逐 provider 热更（免费源 + 订阅全量；provider 全量替换语义）。
  // M5：PUT 404 = provider 名不在运行实例的 config（sources.yaml 新增源）→ 明示需 restart
  let providersUpdated = 0;
  const newProviders = [];
  const rt = await probeKernel();
  if (rt) {
    const entries = config.listProviderEntries();
    for (const entry of entries) {
      const r = await api.request(rt.api_port, rt.secret, 'PUT',
        '/providers/proxies/' + encodeURIComponent(entry.name), 8000);
      if (r && (r.status === 200 || r.status === 204)) providersUpdated++;
      else if (r && r.status === 404) newProviders.push(entry.name); // 新增源：运行实例无此 provider
    }
    lines.push('kernel running: ' + providersUpdated + '/' + entries.length + ' providers hot-reloaded');
    if (newProviders.length) {
      lines.push('Note: new provider(s) not in running config: ' + newProviders.join(', ') +
        ' -- restart required to activate (config regenerated, applies on restart)');
    }
  } else {
    lines.push('kernel not running: cache refreshed only (config regen: ' + configRegen + ')');
    lines.push('kernel not running: export skipped');
  }

  // ④ t7 自动导出：更新+热更有成果（providers_updated>0 或源刷新 ok）且内核在跑 →
  //    延迟 Top N 导出。独立异常边界：失败仅警告，绝不改变 update 退出码。
  if (rt && (providersUpdated > 0 || refresh.okCount > 0)) {
    try {
      const ex = await exportTop({});
      if (ex) {
        lines.push('Top export: ' + ex.exported + ' nodes -> ' + ex.file);
      } else {
        lines.push('Warning: top export skipped (kernel not responding)');
      }
    } catch (e) {
      lines.push('Warning: top export failed: ' + (e && e.message ? e.message : 'unknown'));
    }
  }

  lines.push('sources ok ' + refresh.okCount + '/' + refresh.results.length);
  const out = {
    sources_ok: refresh.okCount,
    sources_failed: refresh.failCount,
    providers_updated: providersUpdated,
    config_regen: configRegen,
  };
  if (newProviders.length) out.new_providers_pending_restart = newProviders;
  emitResult(lines, out);
  return refresh.failCount > 0 ? 2 : 0;
}

module.exports = { handle };
