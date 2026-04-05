const net = require('net');

const host = process.env.SMTP_HOST || 'mail_server';
const port = parseInt(process.env.SMTP_PORT || '25', 10);
const from = process.env.MAIL_FROM || 'shop@company.local';
const to = process.env.MAIL_TO || 'support@company.local';
const subject = process.env.MAIL_SUBJECT || 'Test Mail';
const body = process.env.MAIL_BODY || 'hello from client_a';

const commands = [
  `HELO company.local\r\n`,
  `MAIL FROM:<${from}>\r\n`,
  `RCPT TO:<${to}>\r\n`,
  `DATA\r\n`,
  `Subject: ${subject}\r\n\r\n${body}\r\n.\r\n`,
  `QUIT\r\n`
];

const client = net.createConnection({ host, port }, () => {
  console.log(`connected to ${host}:${port}`);
});

let step = 0;
client.on('data', (data) => {
  const msg = data.toString();
  process.stdout.write(msg);
  if (/^\d{3} /.test(msg.trim())) {
    if (step < commands.length) {
      client.write(commands[step]);
      step++;
    } else {
      client.end();
    }
  }
});

client.on('error', (err) => {
  console.error('SMTP error:', err.message);
});

client.on('end', () => {
  console.log('done');
});