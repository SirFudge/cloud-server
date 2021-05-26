#!/bin/bash

#made with/for Ubuntu 20.4
#by Joey Nijsten
#4/21/2021
echo 'welcome to the nextcloud all-in-one installation script.
- made with/for Ubuntu 20.4
- by Joey Nijsten
- 4/21/2021'

#update apt
apt update -y

#install ftp/sftp
echo 'Installing vsftpd for FTP and SFTP'
apt install -y vsftpd

#install Php7.4 MariaDB and certbot
echo 'Installing PHP7.4, MariaDB and Certbot.'
apt -y install php7.4 php7.4-{cli,gd,mysql,pdo,mbstring,tokenizer,bcmath,xml,fpm,curl,zip}
apt install mariadb-server -y

#webserver installation choice.

echo 'Choose a webserver, Apache or Nginx'
sleep 3

read -r webserver

#install Apache2 and certbot.

if [ "$webserver" == 'apache' ]

then

echo 'Installing Apache2.'

apt install -y apache2

apt install -y certbot

apt install -y python3-certbot-apache

fi

#install Nginx and certbot.

if [ "$webserver" == 'nginx' ]

then

echo 'Installing Nginx.'

apt install -y nginx

apt install -y certbot

apt install -y python3-certbot-nginx

fi

#install unzip
apt-get install -y unzip

#install nextcloud
echo 'Installation of NextCloud starting'
sleep 3
echo 'Choose a installation directory'

read directory
mkdir $directory
wget -O $directory/nextcloud.zip https://download.nextcloud.com/server/releases/nextcloud-21.0.1.zip
wait -n
unzip -d $directory/nextcloud.zip $directory/nextcloud/


#Security (OpenSSH can be done at the installation of the OS)
#setup tls sftp
echo 'Enabling tls for SFTP.'
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
echo 'Disabling anominous acces from FTP/SFTP.'
sed 's/anonymous_enable=YES/anonymous_enable=NO/g' /etc/vsftpd.conf

#restart/start services
echo 'Staring or restarting installed services.'
systemctl restart vsftpd
systemctl start mariadb
systemctl enable mariadb

#Firewall enable and rules

#Final message

echo 'Installation finished!'

echo "All application have been installed and the basic security configurations have been set, the script will now stop."

#Exit the script

exit 0
