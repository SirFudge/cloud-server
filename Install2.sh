#NextCloud installation script. 
#Made by Joey Nijsten/SirFudge
#For Ubuntu 20.04
#GNU General Public License v3.0

echo "welcome to the nextcloud all-in-one installation script. "

#update apt
apt update -y

#install Php7.4 MariaDB and certbot
echo 'Installing PHP7.4, MariaDB and Certbot.'

apt -y install php7.4 php7.4-{cli,gd,mysql,pdo,mbstring,tokenizer,bcmath,xml,fpm,curl,zip}

apt install mariadb-server -y

systemctl start mariadb
systemctl enable mariadb

#webserver installation choice.

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
echo "Starting the configuration of MariaDb"

echo "What should the database user be called? "
read -r username

echo "Please enter a password."
read -r password

echo "Enter the desired database name."
read -r database

#Creating the user and database. 
echo "Creating the user and database."
sleep 2

mysql -uroot -e "CREATE USER $username@localhost IDENTIFIED BY $password;"
mysql -uroot -e "CREATE DATABASE $database;"
mysql -uroot -e "GRANT ALL PRIVILEGES ON $database.* TO '$username'@'localhost';" 
mysql -uroot -e "FLUSH PRIVILEGES;" 

echo "Finished creating the user and database "
echo "The username = $username and the database = $database."
sleep 6

#Configuring apache if installed. 
if [[ "$webserver" == 'apache']] || [[ "$webserver" == 'Apache' ]]

then

echo "Starting the configuration of Apache."

echo "What is the domain name you are going to be using?
"

touch /etc/apache2/sites-available/nextcloud.conf

sed 's//<VirtualHost *:80>
        DocumentRoot "/var/www/nextcloud"
        ServerName '$domain'

        ErrorLog ${APACHE_LOG_DIR}/nextcloud.error
        CustomLog ${APACHE_LOG_DIR}/nextcloud.access combined

        <Directory /var/www/nextcloud/>
            Require all granted
            Options FollowSymlinks MultiViews
            AllowOverride All

           <IfModule mod_dav.c>
               Dav off
           </IfModule>

        SetEnv HOME /var/www/nextcloud
        SetEnv HTTP_HOME /var/www/nextcloud
        Satisfy Any

       </Directory>

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
    ssl_certificate_key /etc/letsencrypt/live/'$domain'/privkey.pem;

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

ln -s /etc/nginx/sites-available/nextcloud.conf

certbot certonly --nginx -d $domain

systemctl restart nginx

fi

#Firewall enable and rules
iptables -I INPUT -p tcp --dport 80 -j fastcgi_intercept_errors
iptables -I INPUT -p tcp --dport 443 -j ACCEPT

#Start NextCloud configuration. 
echo "Starting configuration of NextCloud."
echo "go to http://$domain"
echo "Are you ready to continue? Y/N"
read yesno

##Yes
if [ "$yesno" == 'yes']

then

echo "Continuing script now."

fi

##No
if [ "$yesno" == 'no' ]

then

echo "stopping the installation script."
exit 0

fi

#restart/start services
echo 'Staring or restarting installed services.'
sleep 2

systemctl restart mariadb 

#Final message
echo "All application have been installed and the basic security configurations have been set, the script will now stop."

sleep 5

#Exit the script
exit 0