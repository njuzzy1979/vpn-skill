/**
 * cmd-setup.js — setup 子命令 handler（设计 §4 / §4.1）
 *
 * 行为：`--sub <URL>` 或交互输入 → 写 user/subscriptions.yaml
 * （§4.1 格式：version/name:primary/url/enabled）→ 原子写；
 * user/ 目录不存在则建。
 *
 * R2 铁律：订阅 URL 只入 user/subscriptions.yaml 与生成的 var/config.yaml，
 * 任何 console 输出不回显 URL——JSON 尾块只给 {saved:1, file:...}，
 * 校验失败的错误信息同样不含 URL 本身。
 *
 * 输出协议：英文 ASCII 行 + ===JSON=== + 单行 JSON（设计 §4，GBK 控制台安全）。
 * 退出码：0=成功 / 1=失败。
 */

'use strict';

const fs = require('fs');
const path = require('path');
const yaml = require('../vendor/yaml');
const { atomicWrite } = require('./providers');

const SUBSCRIPTIONS_FILE = path.resolve(__dirname, '..', '..', 'user', 'subscriptions.yaml');

/**
 * 输出协议：英文行 + ===JSON=== + 单行 JSON
 */
function emitResult(lines, obj) {
  for (const l of lines) console.log(l);
  console.log('===JSON===');
  console.log(JSON.stringify(obj));
}

/**
 * 交互式读取订阅 URL（人工兜底入口）。
 * stdin 关闭/EOF（管道调用）时 question 永不 resolve，监听 close 事件
 * 返回 null 走校验拒绝路径——否则进程静默退出 rc=0 违反输出协议。
 */
function promptUrl() {
  const readline = require('node:readline/promises');
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    let settled = false;
    const finish = (v) => {
      if (!settled) {
        settled = true;
        resolve(v);
      }
    };
    rl.on('close', () => finish(null));
    rl.question('Enter subscription URL: ')
      .then((a) => {
        finish(a.trim());
        rl.close();
      })
      .catch(() => finish(null));
  });
}

/**
 * setup handler
 * @param {string[]} argv 子命令后的参数数组
 * @returns {Promise<number>} 退出码
 */
async function handle(argv) {
  let url = null;

  // --sub <URL> 参数形态
  const idx = argv.indexOf('--sub');
  if (idx >= 0 && idx + 1 < argv.length) {
    url = argv[idx + 1].trim();
  } else if (idx >= 0) {
    emitResult(['error: --sub requires a value'], { saved: 0, error: 'missing-value' });
    return 1;
  }

  // 交互兜底（stdin 关闭时 readline 立即 EOF → 空串 → 校验失败路径）
  if (!url) {
    try {
      url = await promptUrl();
    } catch (_) {
      url = '';
    }
  }

  // 校验：http(s) 形态；错误信息不含 URL 本身（R2）
  if (!url || !/^https?:\/\/\S+$/i.test(url)) {
    emitResult(
      ['error: invalid subscription url (must start with http:// or https://)'],
      { saved: 0, error: 'invalid-url' }
    );
    return 1;
  }

  // 写 user/subscriptions.yaml（§4.1 格式；覆盖写=契约幂等语义）
  const doc = {
    version: 1,
    subscriptions: [
      {
        name: 'primary', // 用户可读别名（允许进日志/输出）
        url: url,        // 仅存于此文件与 var/config.yaml（R2）
        enabled: true,
      },
    ],
  };
  try {
    fs.mkdirSync(path.dirname(SUBSCRIPTIONS_FILE), { recursive: true });
    atomicWrite(SUBSCRIPTIONS_FILE, yaml.stringify(doc));
  } catch (e) {
    emitResult(['error: failed to write subscriptions file'], { saved: 0, error: 'write-failed' });
    return 1;
  }

  // 输出不回显 URL（R2）
  emitResult(
    ['subscription saved to user/subscriptions.yaml'],
    { saved: 1, file: 'user/subscriptions.yaml' }
  );
  return 0;
}

module.exports = { handle };
