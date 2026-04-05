FROM php:7.4-apache

RUN apt-get update && apt-get install -y \
    libc-client-dev \
    libkrb5-dev \
 && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/spool/postfix/{active,bounce,corrupt,defer,deferred,flush,hold,incoming,private,public,saved,trace}

RUN docker-php-ext-configure imap --with-kerberos --with-imap-ssl \
 && docker-php-ext-install pdo pdo_mysql mysqli imap

COPY . /var/www/html/
