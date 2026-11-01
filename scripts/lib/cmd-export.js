/**
 * cmd-export.js — export 子命令 handler（t7；自输出形态，与 cmd-update 同构）
 *
 * 行为：exportTop() 经运行中内核的 /proxies 延迟数据 + var/providers 缓存，
 * 生成延迟 Top N **免费**节点文件（var/providers/top100.yaml，clash proxies 格式，固定名
 * 覆盖；t7 增补：仅免费节点，[sub] 订阅节点排除——用户 FlClash 里已有完整订阅）。
 * 延迟数据来自内核 url-test/health-check 的 history——内核不在跑就没有数据源：
 * exportTop 返回 null → rc=1 + 提示 start first。
 *
 * 参数：--top N（默认 100，正整数）。
 *
 * 输出协议：英文 ASCII 行 + ===JSON=== + 单行 JSON（统计量与路径 only——R2：绝不
 * 输出节点名/服务器地址/凭据）。退出码：0=成功 / 1=内核未运行或导出失败。
 */

'use strict';

const exportTop = require('./export-top').exportTop;

/**
 * 输出协议：英文行 + ===JSON=== + 单行 JSON（与 cmd-update 同构）
 */
function emitResult(lines, obj) {
  for (const l of lines) console.log(l);
  console.log('===JSON===');
  console.log(JSON.stringify(obj));
}

/**
 * export handler
 * @param {string[]} argv 子命令后的参数数组（--top N）
 * @returns {Promise<number>} 退出码
 */
async function handle(argv) {
  // --top N（缺省 100；非法值直接失败，不猜意图）
  let top = 100;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--top') {
      const raw = argv[i + 1];
      const v = Number(raw);
      if (!Number.isInteger(v) || v < 1) {
        emitResult(['error: invalid --top value: ' + String(raw)], { error: 'invalid-top', given: String(raw) });
        return 1;
      }
      top = v;
      i++;
    }
  }

  let r;
  try {
    r = await exportTop({ top });
  } catch (e) {
    emitResult(
      ['error: export failed: ' + (e && e.message ? e.message : 'unknown')],
      { error: 'export-failed' }
    );
    return 1;
  }
  if (!r) {
    // 内核未运行（runtime 缺失或 /proxies 无应答）：延迟数据来自运行中的内核
    emitResult(
      ['error: kernel not running (no /proxies response)', 'start first (delay data comes from running kernel)'],
      { error: 'kernel-not-running' }
    );
    return 1;
  }

  emitResult(
    [
      'Exported ' + r.exported + ' nodes (of ' + r.total_candidates + ' free-node candidates with delay data) to ' + r.file,
      'Free nodes only (subscription nodes excluded - you already have them in your sub client).',
      'File contains free-node credentials only (public sources) and ships with the repo as-is.',
    ],
    {
      exported: r.exported,
      total_candidates: r.total_candidates,
      file: r.file,
      top,
      included: r.included,          // 'free-only'
      excluded_sub: r.excluded_sub,  // 候选中排除的 [sub] 前缀节点数
    }
  );
  return 0;
}

module.exports = { handle };
