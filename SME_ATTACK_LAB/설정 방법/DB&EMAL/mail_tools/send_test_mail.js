'use strict';

/**
 * SMTP 테스트 메일 발송 스크립트
 * 새 변수명(MAIL_SMTP_*)과 구 변수명(SMTP_*)을 둘 다 지원.
 * 제목/본문은 명령행 인자 우선, 없으면 환경변수/기본값 사용.
 */

const net = require('net');

const host = process.env.MAIL_SMTP_HOST || process.env.SMTP_HOST || 'mail_server';
const port = parseInt(process.env.MAIL_SMTP_PORT || process.env.SMTP_PORT || '25', 10);
const from = process.env.MAIL_FROM || 'shop@company.local';
const to = process.env.MAIL_TO || 'support@company.local';
const prefix = process.env.MAIL_SUBJECT_PREFIX || '[client]';
const subject = process.argv[2] || process.env.MAIL_SUBJECT || `${prefix} test mail`;
const body = process.argv[3] || process.env.MAIL_BODY || `Generated at ${new Date().toISOString()}\nSource container: ${process.env.HOSTNAME || 'node-client'}`;

const commands = [
  `HELO company.local`,
  `MAIL FROM:<${from}>`,
  `RCPT TO:<${to}>`,
  'DATA',
  [
    `From: ${from}`,
    `To: ${to}`,
    `Subject: ${subject}`,
    `Date: ${new Date().toUTCString()}`,
    `Message-ID: <${Date.now()}.${Math.random().toString(16).slice(2)}@${process.env.HOSTNAME || 'node-client'}>`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=UTF-8',
    '',
    body,
    '.'
  ].join('\r\n'),
  'QUIT'
];

const expected = [
  /^220 /,
  /^250 /,
  /^250 /,
  /^250 |^251 /,
  /^354 /,
  /^250 /,
  /^221 /
];

let step = 0;
let buffer = '';

const client = net.createConnection({ host, port }, () => {
  console.log(`connected to ${host}:${port}`);
});
client.setEncoding('utf8');
client.setTimeout(10000);

client.on('data', (data) => {
  buffer += data;
  const lines = buffer.split(/\r?\n/).filter(Boolean);
  const last = lines[lines.length - 1] || '';
  if (!/^\d{3}[ -]/.test(last)) return;

  if (!expected[step].test(last)) {
    console.error('SMTP unexpected response:', last);
    client.destroy();
    process.exit(1);
  }

  if (step < commands.length) {
    client.write(commands[step] + '\r\n');
  } else {
    console.log('MAIL SENT OK');
    client.end();
  }
  step += 1;
  buffer = '';
});

client.on('timeout', () => {
  console.error('SMTP timeout');
  client.destroy();
  process.exit(1);
});

client.on('error', (err) => {
  console.error('SMTP error:', err.message);
  process.exit(1);
});