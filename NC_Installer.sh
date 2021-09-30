#NextCloud installation script. 
#Made by SirFudge
#For Ubuntu 20.04
#Branch Bugs
#GNU General Public License v3.0

echo 'Welcome to the all-in-one installation script for NextCloud.'
echo 'This is a Bug Branch, beware!'

#update apt
apt update -y

#install Php7.4 MariaDB and certbot
echo 'Installing PHP7.4, MariaDB and Certbot.'
echo "Do you want to continue? Y/N"
read yesno1

while [[ "$yesno1" == 'no' ]] || [[ "$yesno1" == 'No' ]]

do

echo "Do you want to quit?"
read qyesno1

if  [[ "$qyesno1" == 'yes' ]] || [[ "$qyesno1" == 'Yes' ]]

then

echo "Stopping the installation script."
exit 0

elif [[ "$qyesno1" == 'no' ]] || [[ "$qyesno1" == 'No' ]]

then

echo "Are you ready to continue? Y/N"
read yesno1

fi

done


apt -y install php7.4 php7.4-{cli,gd,mysql,pdo,mbstring,tokenizer,bcmath,xml,fpm,curl,zip}

apt install mariadb-server -y

systemctl start mariadb
systemctl enable mariadb

#webserver installation choice.
echo "About to pick a webserver, do you want to continue? Y/N"
read yesno2

while [[ "$yesno2" == 'no' ]] || [[ "$yesno2" == 'No' ]]

do

echo "Do you want to quit?"
read qyesno2

if  [[ "$qyesno2" == 'yes' ]] || [[ "$qyesno2" == 'Yes' ]]

then

echo "Stopping the installation script."
exit 0

elif [[ "$qyesno2" == 'no' ]] || [[ "$qyesno2" == 'No' ]]

then

echo "About to pick a webserver, do you want to continue? Y/N"
read yesno2

fi

done


echo 'Choose a webserver, Apache or Nginx'
sleep 3

read -r webserver

#install Apache2 and certbot.

if [[ "$webserver" == 'apache']] || [[ "$webserver" == 'Apache' ]] 

then

echo 'Installing Apache2.'

apt install -y apache2

apt install -y certbot

apt install -y python3-certbot-apache

fi

#install Nginx and certbot.

if [[ "$webserver" == 'nginx']] || [[ "$webserver" == 'Nginx' ]]

then

echo 'Installing Nginx.'

apt install -y nginx

apt install -y certbot

apt install -y python3-certbot-nginx

fi

#install unzip
apt-get install -y unzip

#install nextcloud
echo "starting installation nextcloud, do you want to continue? Y/N"
read yesno3

while [[ "$yesno3" == 'no' ]] || [[ "$yesno3" == 'No' ]]

do

echo "Do you want to quit?"
read qyesno3

if  [[ "$qyesno3" == 'yes' ]] || [[ "$qyesno3" == 'Yes' ]]

then

echo "Stopping the installation script."
exit 0

elif [[ "$qyesno3" == 'no' ]] || [[ "$qyesno3" == 'No' ]]

then

echo "starting installation nextcloud, do you want to continue? Y/N"
read yesno3

fi

done

echo 'Installation of NextCloud starting'
sleep 3

echo 'Choose a download directory'
read directory

mkdir $directory
mkdir /var/www/nextcloud

wget -O $directory/nextcloud.zip https://download.nextcloud.com/server/releases/nextcloud-21.0.1.zip

wait -n

unzip -d $directory/nextcloud.zip /var/www/nextcloud/


#Configuring MariaDB
echo 'Starting the configuration of MariaDb'

echo 'What should the database user be called?'
read -r username

echo 'Please enter a password.'
read -r password

echo 'Enter the desired database name.'
read -r database

##Creating the user and database. 
echo 'Creating the user and database.'
sleep 2

mysql -uroot -e "CREATE USER $username@localhost IDENTIFIED BY $password;"
mysql -uroot -e "CREATE DATABASE $database;"
mysql -uroot -e "GRANT ALL PRIVILEGES ON $database.* TO '$username'@'localhost';" 
mysql -uroot -e "FLUSH PRIVILEGES;" 

echo 'Finished creating the user and database'
echo 'The username = $username and the database = $database.'
sleep 6

#restart MariaDB
systemctl restart mariadb 

#What should the domain be? 
echo "What is the domain name you are going to be using?
"
read domain

#Configuring apache if installed. 
if [[ "$webserver" == 'apache']] || [[ "$webserver" == 'Apache' ]]

then

echo 'Starting the configuration of Apache.'

chown www-data:www-data /var/www/nextcloud-data

touch /etc/apache2/sites-available/nextcloud.conf

sed 's//<IfModule mod_ssl.c>
    <VirtualHost *:443>
        DocumentRoot /var/www/nextcloud/;
        ServerName '$domain';


        <Directory /var/www/nextcloud/>
            Options +FollowSymlinks
            AllowOverride All
            Require all granted
                <IfModule mod_dav.c>
                    Dav off
                </IfModule>
                SetEnv HOME /var/www/nextcloud
                SetEnv HTTP_HOME /var/www/nextcloud
        </Directory>

        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined

ServerAlias '$domain';
Include /etc/letsencrypt/options-ssl-apache.conf
SSLCertificateFile /etc/letsencrypt/live/'$domain'/fullchain.pem
SSLCertificateKeyFile /etc/letsencrypt/live/'$domain'/privkey.pem
</VirtualHost>
</IfModule>
<VirtualHost *:80>
    ServerName '$domain';

    Redirect / https://'$domain';

</VirtualHost>/g' /etc/apache2/sites-available/nextcloud.conf

a2ensite nextcloud.conf
a2enmod rewrite headers env dir mime setenvif
apache2ctl -t

apt install imagemagick php-imagick libapache2

systemctl reload apache2

certbot --apache -d $domain

fi

#Configuring Nginx if installed. 
if [[ "$webserver" == 'nginx']] || [[ "$webserver" == 'Nginx' ]]

then

touch /etc/nginx/sites-available/nextcloud.conf

sed 's//upstream php-handler {
    server 127.0.0.1:9000;
    #server unix:/var/run/php/php7.4-fpm.sock;
}

server {
    listen 80;
    listen [::]:80;
    server_name '$domain';

    # Enforce HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443      ssl http2;
    listen [::]:443 ssl http2;
    server_name '$domain';

    # Use Mozillas guidelines for SSL/TLS settings
    # https://mozilla.github.io/server-side-tls/ssl-config-generator/
    ssl_certificate     /etc/letsencrypt/live/'$domain'/fullchain.pem;
    ssl_certificate_key     /etc/letsencrypt/live/'$domain'/privkey.pem;

    # HSTS settings
    # WARNING: Only add the preload option once you read about
    # the consequences in https://hstspreload.org/. This option
    # will add the domain to a hardcoded list that is shipped
    # in all major browsers and getting removed from this list
    # could take several months.
    #add_header Strict-Transport-Security "max-age=15768000; includeSubDomains; preload;" always;

    # set max upload size
    client_max_body_size 512M;
    fastcgi_buffers 64 4K;

    # Enable gzip but do not remove ETag headers
    gzip on;
    gzip_vary on;
    gzip_comp_level 4;
    gzip_min_length 256;
    gzip_proxied expired no-cache no-store private no_last_modified no_etag auth;
    gzip_types application/atom+xml application/javascript application/json application/ld+json application/manifest+json application/rss+xml application/vnd.geo+json application/vnd.ms-fontobject application/x-font-ttf application/x-web-app-manifest+json application/xhtml+xml application/xml font/opentype image/bmp image/svg+xml image/x-icon text/cache-manifest text/css text/plain text/vcard text/vnd.rim.location.xloc text/vtt text/x-component text/x-cross-domain-policy;

    # Pagespeed is not supported by Nextcloud, so if your server is built
    # with the `ngx_pagespeed` module, uncomment this line to disable it.
    #pagespeed off;

    # HTTP response headers borrowed from Nextcloud `.htaccess`
    add_header Referrer-Policy                      "no-referrer"   always;
    add_header X-Content-Type-Options               "nosniff"       always;
    add_header X-Download-Options                   "noopen"        always;
    add_header X-Frame-Options                      "SAMEORIGIN"    always;
    add_header X-Permitted-Cross-Domain-Policies    "none"          always;
    add_header X-Robots-Tag                         "none"          always;
    add_header X-XSS-Protection                     "1; mode=block" always;

    # Remove X-Powered-By, which is an information leak
    fastcgi_hide_header X-Powered-By;

    # Path to the root of your installation
    root /var/www/nextcloud;

    # Specify how to handle directories -- specifying `/index.php$request_uri`
    # here as the fallback means that Nginx always exhibits the desired behaviour
    # when a client requests a path that corresponds to a directory that exists
    # on the server. In particular, if that directory contains an index.php file,
    # that file is correctly served; if it doesnt, then the request is passed to
    # the front-end controller. This consistent behaviour means that we dont need
    # to specify custom rules for certain paths (e.g. images and other assets,
    # `/updater`, `/ocm-provider`, `/ocs-provider`), and thus
    # `try_files $uri $uri/ /index.php$request_uri`
    # always provides the desired behaviour.
    index index.php index.html /index.php$request_uri;

    # Rule borrowed from `.htaccess` to handle Microsoft DAV clients
    location = / {
        if ( $http_user_agent ~ ^DavClnt ) {
            return 302 /remote.php/webdav/$is_args$args;
        }
    }

    location = /robots.txt {
        allow all;
        log_not_found off;
        access_log off;
    }

    # Make a regex exception for `/.well-known` so that clients can still
    # access it despite the existence of the regex rule
    # `location ~ /(\.|autotest|...)` which would otherwise handle requests
    # for `/.well-known`.
    location ^~ /.well-known {
        # The rules in this block are an adaptation of the rules
        # in `.htaccess` that concern `/.well-known`.

        location = /.well-known/carddav { return 301 /remote.php/dav/; }
        location = /.well-known/caldav  { return 301 /remote.php/dav/; }

        location /.well-known/acme-challenge    { try_files $uri $uri/ =404; }
        location /.well-known/pki-validation    { try_files $uri $uri/ =404; }

        # Let Nextclouds API for `/.well-known` URIs handle all other
        # requests by passing them to the front-end controller.
        return 301 /index.php$request_uri;
    }

    # Rules borrowed from `.htaccess` to hide certain paths from clients
    location ~ ^/(?:build|tests|config|lib|3rdparty|templates|data)(?:$|/)  { return 404; }
    location ~ ^/(?:\.|autotest|occ|issue|indie|db_|console)                { return 404; }

    # Ensure this block, which passes PHP files to the PHP process, is above the blocks
    # which handle static assets (as seen below). If this block is not declared first,
    # then Nginx will encounter an infinite rewriting loop when it prepends `/index.php`
    # to the URI, resulting in a HTTP 500 error response.
    location ~ \.php(?:$|/) {
        fastcgi_split_path_info ^(.+?\.php)(/.*)$;
        set $path_info $fastcgi_path_info;

        try_files $fastcgi_script_name =404;

        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_param PATH_INFO $path_info;
        fastcgi_param HTTPS on;

        fastcgi_param modHeadersAvailable true;         # Avoid sending the security headers twice
        fastcgi_param front_controller_active true;     # Enable pretty urls
        fastcgi_pass php-handler;

        fastcgi_intercept_errors on;
        fastcgi_request_buffering off;
    }

    location ~ \.(?:css|js|svg|gif)$ {
        try_files $uri /index.php$request_uri;
        expires 6M;         # Cache-Control policy borrowed from `.htaccess`
        access_log off;     # Optional: Dont log access to assets
    }

    location ~ \.woff2?$ {
        try_files $uri /index.php$request_uri;
        expires 7d;         # Cache-Control policy borrowed from `.htaccess`
        access_log off;     # Optional: Dont log access to assets
    }

    # Rule borrowed from `.htaccess`
    location /remote {
        return 301 /remote.php$request_uri;
    }

    location / {
        try_files $uri $uri/ /index.php$request_uri;
    }
}/g' /etc/nginx/sites-available/nextcloud.conf

certbot certonly --nginx -d $domain

ln -s /etc/nginx/sites-available/nextcloud.conf /etc/nginx/sites-enabled/nextcloud.conf

systemctl restart nginx

fi

#Enable firewall and rules. 
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
#Allow SSH.
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
##Allow http.
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
##Allow https. 
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
##Drop default rules
iptables -P INPUT DROP 
##Save rules
iptables-save > /etc/iptables/rules.v4
##Make loading of rules automatic. 
apt-get install iptables-persistent

wait -n

#Start NextCloud configuration. 
echo "Starting configuration of NextCloud."
echo "go to https://$domain"

sleep 60

##Ready with Configuring NextCloud? Yes continue script, No gives option to stop else you get into a loop till you are done or quit. 
echo "Are you ready to continue? Y/N"
read yesno

while [[ "$yesno" == 'no' ]] || [[ "$yesno" == 'No' ]]

do

echo "Do you want to quit?"
read qyesno

if  [[ "$qyesno" == 'yes' ]] || [[ "$qyesno" == 'Yes' ]]

then

echo "Stopping the installation script."
exit 0

elif [[ "$qyesno" == 'no' ]] || [[ "$qyesno" == 'No' ]]

then

echo "Are you ready to continue? Y/N"
read yesno

fi

done

#Install fail2ban. 
apt install fail2ban
##Configuring fail2ban. 
cp /etc/fail2ban/jail.{conf,local}

sed -i 's/#ignoreip = 127.0.0.1/8 ::1/ignoreip = 127.0.0.1/8 ::1/g' /etc/fail2ban/jail.local

systemctl restart fail2ban

#Final message
echo "All application have been installed and the basic security configurations have been set, the script will now stop."

sleep 5

#Exit the script
exit 0
