FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt update && apt install -y \
    postfix \
    dovecot-core \
    dovecot-imapd \
    dovecot-lmtpd \
    supervisor \
    rsyslog \
    ssl-cert \
    telnet \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -g 5000 vmail && useradd -g vmail -u 5000 vmail -d /var/mail

RUN mkdir -p /var/spool/postfix/public \
    /var/spool/postfix/private \
    /var/spool/postfix/pid \
    /var/spool/postfix/maildrop

RUN mkdir -p /var/mail/vhosts/company.local \
    /var/spool/postfix/private \
    /var/log/supervisor

COPY postfix/main.cf /etc/postfix/main.cf
COPY postfix/master.cf /etc/postfix/master.cf
COPY postfix/vmailbox /etc/postfix/vmailbox
COPY dovecot/dovecot.conf /etc/dovecot/dovecot.conf
COPY dovecot/10-mail.conf /etc/dovecot/conf.d/10-mail.conf
COPY dovecot/10-auth.conf /etc/dovecot/conf.d/10-auth.conf
COPY dovecot/10-master.conf /etc/dovecot/conf.d/10-master.conf
COPY dovecot/users /etc/dovecot/users
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

RUN postmap /etc/postfix/vmailbox \
    && chown -R vmail:vmail /var/mail/vhosts

EXPOSE 25 587 143

CMD ["/usr/bin/supervisord", "-n"]