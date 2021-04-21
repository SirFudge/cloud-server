#!/bin/bash

#made with/for Ubuntu 20.4
#by Joey Nijsten
#4/21/2021

#update apt
apt update -y

#install ftp/sftp
apt install -y vsftpd

#install Php7.4, Nginx and certbot
apt -y install php7.4 php7.4-{cli,gd,mysql,pdo,mbstring,tokenizer,bcmath,xml,fpm,curl,zip}
apt install -y nginx
apt install -y certbot

#Security (OpenSSH can be done at the installation of the OS)
#setup tls sftp
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/vsftpd.pem -out /etc/ssl/private/vsftpd.pem
sed -i "ssl_enable=YES
rsa_cert_file=/etc/ssl/private/vsftpd.pem
rsa_private_key_file=/etc/ssl/private/vsftpd.pem
allow_anon_ssl=NO
force_local_data_ssl=YES
force_local_logins_ssl=YES
ssl_tlsv1=YES
ssl_sslv2=NO
ssl_sslv3=NO
require_ssl_reuse=NO
ssl_ciphers=HIGH" /etc/vsftpd.conf

#Disable anominous acces fpt/sftp
sed 's/anonymous_enable=YES/anonymous_enable=NO/g' /etc/vsftpd.conf

#restart services
systemctl restart vsftpd

#Firewall enable and rules