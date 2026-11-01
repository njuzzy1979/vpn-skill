#!/usr/bin/env node
// vpn.js — vpn-skill 唯一 CLI 入口（§4）：子命令路由表（全部 10 个）+ 输出协议（英文 ASCII 行 +
// ===JSON=== 尾块单行 JSON）+ 退出码（0=成功 / 1=失败 / 2=成功带警告）
// t1-t4 批 9 子命令：bootstrap/setup/start/stop/restart/status/update/test/doctor
// （cmd-test/cmd-doctor 与 cmd-setup/cmd-update 同构：自输出形态，handler 返回退出码数字）
// t7 追加 export：延迟 Top N 节点导出（cmd-export 与 cmd-update 同构）
'use strict';

const fs = require('fs');
const path = require('path');

const util = require('./lib/util');

// 子命令路由表：mod 相对 scripts/，fn 为模块内 handler 名（统一签名 async (args) -> {lines, json, rc}）
const ROUTES = {
  bootstrap: { mod: './lib/bootstrap', fn: 'run' },
  setup:     { mod: './lib/cmd-setup', fn: 'handle' },   // t2（自输出形态：返回退出码数字）
  start:     { mod: './lib/core',     fn: 'cmdStart' },
  stop:      { mod: './lib/core',     fn: 'cmdStop' },
  restart:   { mod: './lib/core',     fn: 'cmdRestart' }, // t4：stop+start 组合（幂等）
  status:    { mod: './lib/core',     fn: 'cmdStatus' },
  update:    { mod: './lib/cmd-update', fn: 'handle' },   // t2（自输出形态：返回退出码数字）
  test:      { mod: './lib/cmd-test', fn: 'handle' },     // t4（自输出形态：返回退出码数字）
  doctor:    { mod: './lib/cmd-doctor', fn: 'handle' },   // t4（自输出形态：返回退出码数字）
  export:    { mod: './lib/cmd-export', fn: 'handle' },   // t7（自输出形态：延迟 Top N 节点导出）
};

const USAGE = [
  'Usage: node vpn.js <subcommand>',
  'Subcommands: bootstrap setup start stop restart status update test doctor export',
  'Exit codes: 0=ok 1=failed 2=ok-with-warnings',
];

async function main() {
  const argv = process.argv.slice(2);
  const cmd = argv[0];
  const args = argv.slice(1);

  if (!cmd || !ROUTES[cmd]) {
    util.emitResult(USAGE, { error: 'unknown-subcommand', given: cmd || null }, 1);
    return;
  }

  // 懒加载：模块文件存在且导出该 handler 才调用；否则 handler-missing + rc=2
  // （t4 起 9 子命令全部落地，本分支为纯防御——正常不可达）
  const route = ROUTES[cmd];
  const modPath = path.resolve(__dirname, route.mod + '.js');
  let handler = null;
  if (fs.existsSync(modPath)) {
    const m = require(modPath); // eslint-disable-line global-require
    handler = m[route.fn];
  }
  if (typeof handler !== 'function') {
    util.emitResult(
      ['Subcommand handler missing: ' + cmd, 'No action taken.'],
      { subcommand: cmd, status: 'handler-missing', handler_module: route.mod, handler_fn: route.fn },
      2,
    );
    return;
  }

  const result = await handler(args);
  if (typeof result === 'number') {
    // 自输出形态 handler（t2 cmd-*.js）：已按输出协议自行打印，返回值即退出码
    process.exit(result);
  }
  util.emitResult(result.lines, result.json, result.rc);
}

main().catch(e => {
  // 兜底：未捕获异常按失败退出（错误信息 ASCII 化）
  util.emitResult(['Error: ' + (e && e.message ? e.message : String(e))], { error: String(e && e.message || e) }, 1);
});
