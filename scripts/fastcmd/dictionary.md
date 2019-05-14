--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
#### NGINX
--------------------------------------------------------------------------------------------------------
service nginx stop
systemctl stop nginx

killall -9 nginx

service nginx quit
systemctl quit nginx

service nginx reload
systemctl reload nginx

nginx -t
service nginx configtest
systemctl config nginx

service nginx -V
systemctl -V nginx
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
#### HTTPD
--------------------------------------------------------------------------------------------------------
sudo service httpd start
​sudo service httpd stop
​sudo service httpd restart
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
#### Liquibase
--------------------------------------------------------------------------------------------------------
UPDATE DATABASECHANGELOGLOCK SET LOCKED=FALSE, LOCKGRANTED=null, LOCKEDBY=null where ID=1;
DELETE FROM DATABASECHANGELOGLOCK;
Drop DATABASE DATABASECHANGELOGLOCK;

<changeSet author="user" id="123">
  <preConditions onFail="CONTINUE">
    <not><sequenceExists sequenceName="SEQUENCE_NAME_SEQ" /></not>
  </preConditions>
  <createSequence sequenceName="SEQUENCE_NAME_SEQ"/>
</changeSet>

  <changeSet author="user" id="123">
  <preConditions onFail="CONTINUE">
          <sqlCheck expectedResult="0">
            select count(*) from user_sequences where sequence_name = 'SEQUENCE_NAME_SEQ';
          </sqlCheck>
  </preConditions>
  <createSequence sequenceName="SEQUENCE_NAME_SEQ"/>
</changeSet>

java -jar liquibase.jar --changeLogFile="./data/<insert file name> " --diffTypes="data" generateChangeLog

liquibase --changeLogFile=mydb.xml generateChangeLog
liquibase --changeLogFile=mydb.xml changelogSync
liquibase --changeLogFile=mydb.xml update
--------------------------------------------------------------------------------------------------------
<changeSet author="e-ballo" id="DropViewsAndcreateSynonyms" context="dev,int,uat,prod">
    <preConditions onFail="CONTINUE" >
        <viewExists viewName="PMV_PACKAGE_ITEMS" schemaName="ZON"/>
        <viewExists viewName="PMV_SUBSPLAN_INSTALLTYPES" schemaName="ZON"/>
    </preConditions>
    <dropView schemaName="ZON" viewName="PMV_PACKAGE_ITEMS"  />
    <dropView schemaName="ZON" viewName="PMV_SUBSPLAN_INSTALLTYPES"  />
    <sqlFile path="environment-synonyms.sql" relativeToChangelogFile="true" splitStatements="true" stripComments="true"/>
</changeSet>
--------------------------------------------------------------------------------------------------------
Standard Migrator Run
java -jar liquibase.jar \
      --driver=oracle.jdbc.OracleDriver \
      --classpath=\path\to\classes:jdbcdriver.jar \
      --changeLogFile=com/example/db.changelog.xml \
      --url="jdbc:oracle:thin:@localhost:1521:oracle" \
      --username=scott \
      --password=tiger \
      update
Run Migrator pulling changelogs from a .WAR file
java -jar liquibase.jar \
      --driver=oracle.jdbc.OracleDriver \
      --classpath=website.war \
      --changeLogFile=com/example/db.changelog.xml \
      --url=jdbc:oracle:thin:@localhost:1521:oracle \
      --username=scott \
      --password=tiger \
      update
Run Migrator pulling changelogs from an .EAR file
java -jar liquibase.jar \
      --driver=oracle.jdbc.OracleDriver \
      --classpath=application.ear \
      --changeLogFile=com/example/db.changelog.xml \
      --url=jdbc:oracle:thin:@localhost:1521:oracle \
      --username=scott \
      --password=tiger
Don’t execute changesets, save SQL to /tmp/script.sql
java -jar liquibase.jar \
        --driver=oracle.jdbc.OracleDriver \
        --classpath=jdbcdriver.jar \
        --url=jdbc:oracle:thin:@localhost:1521:oracle \
        --username=scott \
        --password=tiger \
        updateSQL > /tmp/script.sql
List locks on the database change log
java -jar liquibase.jar \
        --driver=oracle.jdbc.OracleDriver \
        --classpath=jdbcdriver.jar \
        --url=jdbc:oracle:thin:@localhost:1521:oracle \
        --username=scott \
        --password=tiger \
        listLocks
Unicode
MySQL
Add url parameters useUnicode=true and characterEncoding=UTF-8 to set character encoding to utf8.
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
#### ROUTE
--------------------------------------------------------------------------------------------------------
route add 10.1.1.140 netmask 255.255.255.255 <defaultGW> -P
route print
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
#### MISC
--------------------------------------------------------------------------------------------------------
@echo off

:: Connecting to VPN...
rasdial "VPN Name" user pass

echo Running RDP...
"Connect to Server.rdp"

echo Finished - disconnecting from VPN...
rasdial "VPN Name" /disconnect
--------------------------------------------------------------------------------------------------------
systemctl enable myunit
systemctl -l status myunit
systemctl start myunit
systemctl daemon-reload
--------------------------------------------------------------------------------------------------------
git -c diff.mnemonicprefix=false -c core.quotepath=false --no-optional-locks stash save version_01
git -c diff.mnemonicprefix=false -c core.quotepath=false --no-optional-locks stash apply stash@{0}

git -c diff.mnemonicprefix=false -c core.quotepath=false --no-optional-locks fetch origin
git -c diff.mnemonicprefix=false -c core.quotepath=false --no-optional-locks pull --no-commit origin master
--------------------------------------------------------------------------------------------------------
git config merge.tool vimdiff
git config merge.conflictstyle diff3
git config mergetool.prompt false
--------------------------------------------------------------------------------------------------------
git branch -D PDWB-527_kafka_refactoring
--------------------------------------------------------------------------------------------------------
docker run -d --name axonserver -p 8024:8024 -p 8124:8124 axoniq/axonserver
--------------------------------------------------------------------------------------------------------
$ bin/kafka-topics.sh --create \
  --zookeeper localhost:2181 \
  --replication-factor 1 --partitions 1 \
  --topic mytopic
--------------------------------------------------------------------------------------------------------
$ bin/kafka-topics.sh --create --zookeeper localhost:2181 --replication-factor 1 --partitions 1 --topic baeldung
$ bin/kafka-topics.sh --create --zookeeper localhost:2181 --replication-factor 1 --partitions 5 --topic partitioned
$ bin/kafka-topics.sh --create --zookeeper localhost:2181 --replication-factor 1 --partitions 1 --topic filtered
$ bin/kafka-topics.sh --create --zookeeper localhost:2181 --replication-factor 1 --partitions 1 --topic greeting
--------------------------------------------------------------------------------------------------------
% pgpk -a KEYS
% pgpv apache-ant-1.10.5-bin.tar.gz.asc
or
% pgp -ka KEYS
% pgp apache-ant-1.10.5-bin.tar.gz.asc
or
% gpg --import KEYS
% gpg --verify apache-ant-1.10.5-bin.tar.gz.asc
--------------------------------------------------------------------------------------------------------
find ~/.IntelliJIdea* -type d -exec touch -t $(date +"%Y%m%d%H%M") {} ;
--------------------------------------------------------------------------------------------------------
sudo service rsyslog restart
--------------------------------------------------------------------------------------------------------
git remote set-url origin <url>
--------------------------------------------------------------------------------------------------------
git fetch origin
git checkout -b mailer_redis origin/mailer_redis

git fetch origin
git checkout origin/master
git merge --no-ff mailer_redis

git push origin master

git push --set-upstream origin master_redis
--------------------------------------------------------------------------------------------------------
postcss --use autoprefixer -c options.json -o main.css css/*.css
--------------------------------------------------------------------------------------------------------
 scoop bucket add extras
 scoop install alacritty
 
 gem install mustache
--------------------------------------------------------------------------------------------------------
@echo off
rem For each file in your folder
for %%a in (".\*") do (
rem check if the file has an extension and if it is not our script
if "%%~xa" NEQ "" if "%%~dpxa" NEQ "%~dpx0" (
rem check if extension folder exists, if not it is created
if not exist "%%~xa" mkdir "%%~xa"
rem Move the file to directory
move "%%a" "%%~dpa%%~xa\"
))
--------------------------------------------------------------------------------------------------------
find . -maxdepth 1 -type d \( ! -name . \) -exec bash -c "cd '{}' && pwd" \;
find . -name .git -type d -execdir git pull -v ';
For /R %%G in (*.LOG) do Echo REN "%%G" "%%~nG.TXT"
For /R C:\temp\ %%G IN (*.bak) do Echo del "%%G"

for /f "delims=" %i in ('dir /ad/s/b') do cacls "%i" >>"%TEMP%\cacls.log"
for /F %i in ('dir /b *.log') do notepad %i
for %i in (user1 user2 user3 user4 user5 user6) do net user /delete %i
for /F %i in (filename) do net user /delete %i

for %i in (set) do command command-arguments

for /F "tokens=2,4 delims=," %i in (test.txt) do @echo %i %j
for /F "tokens=2,4 delims=," %i in (test.txt) do @echo %i,%j
for /F "tokens=2,4" %i in (test.txt) do @echo %i %j

mstsc /console
mstsc /f
mstsc /v:computername
mstsc RDP_filename

start "" http://www.cnn.com
--------------------------------------------------------------------------------------------------------
powercfg/energy

CALL:ECHORED "Print me in red!"
:ECHORED
%Windir%\System32\WindowsPowerShell\v1.0\Powershell.exe write-host -foregroundcolor Red %1
goto:eof
--------------------------------------------------------------------------------------------------------
An alternative command to list folders and sub folders matching a wildcard is DIR:
C:\> dir /b /s /a:d "C:\Work\reports*"

To loop through each folder programatically, we can wrap that in a FOR /F command: 
C:\> for /f "tokens=*" %G in ('dir /b /s /a:d "C:\Work\reports*"') do echo Found %G

or the same thing in a batch file, with the %'s doubled: 
for /f "tokens=*" %%G in ('dir /b /s /a:d "C:\Work\reports*"') do echo Found %%G
--------------------------------------------------------------------------------------------------------
find . -type f -regex ".*/build/test-results/.*xml" -exec cp {} $CIRCLE_TEST_REPORTS/junit/ \;
--------------------------------------------------------------------------------------------------------
git fetch --unshallow || true
git fetch --tags
--------------------------------------------------------------------------------------------------------
gem install asciidoctor
--------------------------------------------------------------------------------------------------------
docker run -d --name postgres -p 5432:5432 -e POSTGRES_USER=reactive -e POSTGRES_PASSWORD=reactive123 -e POSTGRES_DB=reactive postgres
--------------------------------------------------------------------------------------------------------
$ curl -d '{"name":"Test1"}' -H "Content-Type: application/json" -X POST http://localhost:8095/organizations
$ curl -d '{"name":"Name1", "balance":5000, "organizationId":1}' -H "Content-Type: application/json" -X POST http://localhost:8090/employees
$ curl -d '{"name":"Name2", "balance":10000, "organizationId":1}' -H "Content-Type: application/json" -X POST http://localhost:8090/employees
--------------------------------------------------------------------------------------------------------
$ rm -rf ~/Library/Caches/IntelliJIdea15
$ rm -rf ~/Library/Preferences/IntelliJIdea15
--------------------------------------------------------------------------------------------------------
curl -I https://yourzone-1c6b.kxcdn.com/assets/css/style.css
--------------------------------------------------------------------------------------------------------
cd ~/.ssh
ssh-keygen -o
ssh-add /path/to/your/private.key
cat id_rsa.pub
--------------------------------------------------------------------------------------------------------
systemctl start nginx

service nginx stop
systemctl stop nginx

killall -9 nginx

service nginx reload
systemctl reload nginx

nginx -t

service nginx -v
systemctl -v nginx
--------------------------------------------------------------------------------------------------------
.htaccess#
<IfModule mod_headers.c>
    <FilesMatch "\.(ttf|ttc|otf|eot|woff|font.css|css|js|gif|png|jpe?g|svg|svgz|ico|webp)$">
        Header set Access-Control-Allow-Origin "*"
    </FilesMatch>
</IfModule>
Nginx#
location ~ \.(ttf|ttc|otf|eot|woff|font.css|css|js|gif|png|jpe?g|svg|svgz|ico|webp)$ {
    add_header Access-Control-Allow-Origin "*";
}
--------------------------------------------------------------------------------------------------------
httpd -V
apache2 -M
httpd -M

authn_alias_module
authn_anon_module
authn_dbm_module
authn_default_module
authz_dbm_module
authz_default_module
authnz_ldap_module
cache_module
cgi_module
disk_cache_module
include_module
ldap_module
proxy_balancer_module
proxy_ftp_module
proxy_http_module
proxy_ajp_module
proxy_connect_module
suexec_module
version_module

server {
    server_name origin.example.com;
    listen 80;

    root /var/www/example;
    index index.php index.html index.htm;

    set $cache_path $request_uri;

    # bypass cache for POST requests
    if ($request_method = POST) {
        set $cache_path 'nocache';
    }

    # don't cache login/admin URLs
    if ($request_uri ~* "/(wp-login.php|wp-admin|login.php|backend|admin)") {
        set $cache_path 'nocache';
    }

    # don't cache if there is a cookie called PHPSESSID
    if ($http_cookie ~* "PHPSESSID") {
        set $cache_path 'nocache';
    }

    # bypass cache for logged in users
    if ($http_cookie ~ (wp-postpass|wordpress_|comment_author)_) {
        set $cache_path 'nocache';
    }

    # bypass cache if query string not empty
    if ($query_string) {
        set $cache_path 'nocache';
    }

    location / {
        # this line is specific to Cache Enabler
        try_files /wp-content/cache/cache-enabler/${http_host}${cache_path}index.html $uri $uri/ /index.php?$args;

        if ($cache_path = 'nocache') {
            expires -1;
            add_header Cache-Control no-cache;
        }
    }

    # php7 fastcgi
    location ~ \.php$ {
        fastcgi_split_path_info ^(.+\.php)(/.+)$;
        fastcgi_pass unix:/run/php/php7.0-fpm.sock;
        fastcgi_index index.php;
        include fastcgi_params;
        ...

        fastcgi_intercept_errors on;

        if ($cache_path = 'nocache') {
            expires -1;
            add_header Cache-Control no-cache;
        }
        if ($cache_path != 'nocache') {
            expires +1h;
        }
    }

    # static assets
    location ~* \.(js|css|png|jpg|jpeg|gif|ico)$ {
        log_not_found off;

        add_header Cache-Control "max-age=604800, stale-while-revalidate=86400, stale-if-error=604800";
    }
}
--------------------------------------------------------------------------------------------------------
curl -sL https://raw.githubusercontent.com/richardforth/apache2buddy/master/apache2buddy.pl | perl
--------------------------------------------------------------------------------------------------------
grep processor /proc/cpuinfo | wc -l
--------------------------------------------------------------------------------------------------------
npm install -g caniuse-cmd
caniuse preload

npm install uglify-js -g
uglifyjs jquery-3.2.1.js --output jquery-3.2.1.min.js

uglifyjs jquery-3.2.1.js --compress --mangle --output jquery-3.2.1.min.js

glifyjs jquery-3.2.1.js --compress sequences=true,conditionals=true,booleans=true --mangle --output jquery-3.2.1.min.js
--------------------------------------------------------------------------------------------------------
mkdir /var/www/testsite.com
echo "Hello World" > /var/www/testsite.com/index.php
chmod -R 755 /var/www/testsite.com

cp /etc/nginx/sites-available/default /etc/nginx/sites-available/testsite.com.conf

server {
    listen 80;

    server_name testsite.com;

    rewrite ^ https://testsite.com$request_uri? permanent;
}

server {
    listen 443 ssl http2;

    ssl_certificate /etc/letsencrypt/live/testsite.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/testsite.com/privkey.pem;
    ssl_stapling on;

    server_name testsite.com;

    root /var/www/testsite.com;

    location / {
        try_files $uri /index.php?$args;
    }

    location ~ \.php$ {
        try_files $uri =404;
        fastcgi_split_path_info ^(.+\.php)(/.+)$;
        fastcgi_pass unix:/run/php/php7.0-fpm.sock;
        fastcgi_index index.php;
        include fastcgi_params;
    }
}

map $http_user_agent $ua_device {
    default "desktop";
    "~*(android|bb\d+|meego).+mobile|avantgo|bada\/|blackberry|blazer|compal|elaine|fennec|hiptop|iemobile|ip(hone|od)|iris|kindle|lge\ |maemo|midp|mmp|mobile.+firefox|netfront|opera\ m(ob|in)i|palm(\ os)?|phone|p(ixi|re)\/|plucker|pocket|psp|series(4|6)0|symbian|treo|up\.(browser|link)|vodafone|wap|windows\ ce|xda|xiino/i" "mobile";
    "~*android|ipad|playbook|silk/i" "tablet";
}

autoindex_exact_size; - This directive specifies whether Nginx should display the exact file sizes of the output in the directory index or simply round to the nearest KB, MB, or GB. This directive has 2 options: on | off.
autoindex_format; - This directive specifies what format the Nginx index listing should be outputted to. This directive has 4 options: html | xml | json | jsonp.
autoindex_localtime; - This directive specifies whether the times for the directory listing should be outputted to local time or UTC. This directive has 2 options: on | off.
An example of a location directive using all 4 autoindex options could resemble the following.

location /somedirectory/ {
    autoindex on;
    autoindex_exact_size off;
    autoindex_format html;
    autoindex_localtime on;
}

ln -s /etc/nginx/sites-available/testsite.com.conf /etc/nginx/sites-enabled/testsite.com.conf
service nginx restart
--------------------------------------------------------------------------------------------------------
$ /Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome --remote-debugging-port=9222 --no-first-run --no-default-browser-check --user-data-dir=$(mktemp -d -t 'chrome-remote_data_dir')
--------------------------------------------------------------------------------------------------------
$ curl "https://tools.keycdn.com/geo.json?host={IP or hostname}"
--------------------------------------------------------------------------------------------------------
sudo tail /var/log/apache/access.log
sudo tail /var/log/apache2/access.log

sudo tail /var/log/apache2/error.log

LogFormat "%h %l %u %t \"%r\" %>s %b" common.

Now let’s break down what each section of that log means.

%h - The IP address of the client.
%l - The identity of the client determined by identd on the client’s machine. Will return a hyphen (-) if this information is not available.
%u - The userid of the client if the request was authenticated.
%t - The time that the request was received.
\"%r\" - The request line that includes the HTTP method used, the requested resource path, and the HTTP protocol that the client used.
%>s - The status code that the server sends back to the client.
%b - The size of the object requested

LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\"" combined
CustomLog log/access_log combined
--------------------------------------------------------------------------------------------------------
.htaccess needs to be enabled with AllowOverride

# BEGIN WordPress
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteBase /
    RewriteRule ^index\.php$ - [L]
    RewriteCond %{REQUEST_FILENAME} !-f
    RewriteCond %{REQUEST_FILENAME} !-d
    RewriteRule . /index.php [L]
</IfModule>
# END WordPress

sudo service apache2 restart

<Directory /var/www/wordpress>
    Options Indexes FollowSymLinks MultiViews
    AllowOverride All
    Order allow,deny
    allow from all

    # BEGIN WordPress
    <IfModule mod_rewrite.c>
        RewriteEngine On
        RewriteBase /
        RewriteRule ^index\.php$ - [L]
        RewriteCond %{REQUEST_FILENAME} !-f
        RewriteCond %{REQUEST_FILENAME} !-d
        RewriteRule . /index.php [L]
    </IfModule>
    # END WordPress
</Directory>

sudo apache2ctl -t

location ~ /wp-content/themes/.*\.(js|css)$ {
    add_header Cache-Control no-cache;
}
location ~ genericons\.css {
    add_header Cache-Control no-cache;
}

<FilesMatch "genericons\.css">
    Header set Cache-Control "no-cache"
</FilesMatch>

<FilesMatch "\.(png|xml)$">
    Header set Cache-Control "no-cache"
</FilesMatch>

LogLevel alert rewrite:trace6
--------------------------------------------------------------------------------------------------------
Mac / Linux: traceroute6 2a00:1450:400a:804::2004
Windows: tracert -6 2a00:1450:400a:804::2004
--------------------------------------------------------------------------------------------------------
apt-get update
apt-get install nginx
Once Nginx has been installed, the next step is to disable the default virtual host.

unlink /etc/nginx/sites-enabled/default
Then, we need to create a file within the /etc/nginx/sites-available directory that contains the reverse proxy information. We can name this reverse-proxy.conf for example.

server {
    listen 80;
    location / {
        proxy_pass http://192.x.x.2;
    }
}

ln -s /etc/nginx/sites-available/reverse-proxy.conf /etc/nginx/sites-enabled/reverse-proxy.conf

service nginx configtest
service nginx restart
--------------------------------------------------------------------------------------------------------
sudo vi /etc/network/interfaces

### Start IPV6 static configuration
iface eth0 inet6 static
address 2607:f0d0:2001:000a:0000:0000:0000:0010
netmask 64
gateway 2607:f0d0:2001:000a:0000:0000:0000:0001
### END IPV6 configuration

sudo systemctl restart networking

ifconfig eth0
ip -6 address show eth0
--------------------------------------------------------------------------------------------------------
log_directory = 'pg_log'                    
log_filename = 'postgresql-dateformat.log'
log_statement = 'all'
logging_collector = on
--------------------------------------------------------------------------------------------------------
ALTER DATABASE your_database_name SET log_statement = 'all';
--------------------------------------------------------------------------------------------------------
Header set Custom-Header-Name "Custom Header Value"
add_header Custom-Header-Name "Custom Header Value"
--------------------------------------------------------------------------------------------------------
Ensure that you have the following libraries installed on your server. Otherwise, the mod_cdn module may not work as expected.

sudo apt-get install libxml2-dev libapr1-dev apache2-dev libssl-dev
From your CLI, download the mod_cdn module with the following snippet and change into the mod_cdn-1.1.0 directory once the file has been unzipped.

wget http://agile.internap.com/assets/mod_cdn-1.1.0.tar.gz
Compile the mod_cdn from source against Apache 2.2.7 or higher.

Copy mod_cdn.so to the following directory /usr/lib/apache2/modules/. Additionally, ensure that the cdn.load file contains the following:

LoadFile /usr/lib/libxml2.so.2
LoadFile /usr/lib/libssl.so.0.9.8
LoadModule cdn_module /usr/lib/apache2/modules/mod_cdn.so
Now, we need to copy the cdn.load and cdn.conf files into the /etc/apache2/mods-available/ directory with the following command.

cd /etc/apache2/mods-enabled
cp cdn.load /etc/apache2/mods-available/
cp cdn.conf /etc/apache2/mods-available/
Then, link them from mods-enabled with the following.

ln -s ../mods-available/cdn.conf cdn.conf
ln -s ../mods-available/cdn.load cdn.load
There are a variety of Apache directives that can be used within your configuration file to properly deliver the desired static assets from the CDN instead of the origin server. You must define the following snippet within the if you want to rewrite all of your site’s static assets to use the CDN URL. However, you can also specifically define a set of directives for a particular directory if you do not want to accelerate the entire website.

<IfModule mod_cdn.c>
    CDNHTMLDocType XHTML
    CDNHTMLToServer https://cdn.yourwebsite.com
    CDNHTMLFromServers https://yourwebsite.com
    CDNHTMLRemapURLServer \.png$ i
    CDNHTMLRemapURLServer \.jpg$ i
    CDNHTMLRemapURLServer \.gif$ i
    CDNHTMLRemapURLServer \.css$ i
    CDNHTMLRemapURLServer \.js$ i

    CDNHTMLLinks img src
    CDNHTMLLinks link href
    CDNHTMLLinks object data
    CDNHTMLLinks input src
    CDNHTMLLinks script src
    CDNHTMLLinks a href
</IfModule>
The snippet above enables the Apache CDN configuration by telling the server which extensions should be replaced. The CDNHTMLToServer directive corresponds to your CDN’s Zone URL (e.g. lorem-1c6b.kxcdn.com) or Zone Alias (e.g. cdn.yourwebsite.com). The CDNHTMLFromServers corresponds to your origin domain. The CDNHTMLRemapURLServer directive defines the extensions for which you want to accelerate. Finally, the CDNHTMLLinks directive defines the tag / attribute pair for which the module expects to find links to content in order to replace them.

Once you have defined the snippet from step 5 in your Apache’s configuration file, save your changes and restart Apache with the following command service apache2 restart. Once Apache has restarted, go to your website and view the page source to ensure that the static assets you have defined are being properly rewritten to reflect the CDN URL.
--------------------------------------------------------------------------------------------------------
server {
    listen 80;
    server_name domain.com www.domain.com;
    return 301 https://domain.com$request_uri;
}

RewriteEngine On
RewriteCond %{HTTPS} off
RewriteRule (.*) https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]

<configuration>
    <system.webServer>
        <rewrite>
            <rules>
                <rule name="https redirect">
                    <match url="(.*)" ignoreCase="false" />
                    <conditions>
                        <add input="{HTTPS}" pattern="off" ignoreCase="false" />
                    </conditions>
                    <action type="Redirect" redirectType="Found" url="https://{HTTP_HOST}{REQUEST_URI}" />
                </rule>
            </rules>
        </rewrite>
    </system.webServer>
</configuration>
--------------------------------------------------------------------------------------------------------
mysqladmin -u userX -p oldpassword newpassword

/etc/init.d/mysql stop
mysqld_safe --skip-grant-tables &
mysql -u root
use mysql;
update user set password=PASSWORD("newpassword") where User='root';
flush privileges;
quit
/etc/init.d/mysql stop
/etc/init.d/mysql start
--------------------------------------------------------------------------------------------------------
server {
    listen 443 ssl http2;

    ssl_certificate server.crt;
    ssl_certificate_key server.key;
}
service nginx reload
--------------------------------------------------------------------------------------------------------
log_format combined '$remote_addr - $remote_user [$time_local]'
    '"$request" $status $body_bytes_sent '
    '"$http_referer" "$http_user_agent"';
access_log /var/log/nginx/access.log log_file combined;
	
error_log /var/log/nginx/error.log warn;

debug - Useful debugging information to help determine where the problem lies.
info - Informational messages that aren’t necessary to read but may be good to know.
notice - Something normal happened that is worth noting.
warn - Something unexpected happened, however is not a cause for concern.
error - Something was unsuccessful.
crit - There are problems that need to be critically addressed.
alert - Prompt action is required.
emerg - The system is in an unusable state and requires immediate attention.

awk '{print $9}' access.log | sort | uniq -c | sort -rn
awk '($9 ~ /302/)' access.log | awk '{print $7}' | sort | uniq -c | sort -rn
--------------------------------------------------------------------------------------------------------
ErrorDocument 403 /forbidden.html
ErrorDocument 404 /notfound.html
ErrorDocument 500 /servererror.html

Header set X-Custom "Custom Value"

order allow,deny
deny from 255.x.x.x
deny from 123.x.x.x
allow from all

RewriteCond %{HTTP_REFERER} unwanteddomain\.com [NC,OR]
RewriteCond %{HTTP_REFERER} unwanteddomain2\.com
RewriteRule .* - [F]

AddType image/gif .gif .GIF

## EXPIRES CACHING ##
<IfModule mod_expires.c>
    ExpiresActive On
    ExpiresByType image/jpg "access 1 year"
    ExpiresByType image/jpeg "access 1 year"
    ExpiresByType image/gif "access 1 year"
    ExpiresByType image/png "access 1 year"
    ExpiresByType text/css "access 1 month"
    ExpiresByType text/html "access 1 month"
    ExpiresByType application/pdf "access 1 month"
    ExpiresByType text/x-javascript "access 1 month"
    ExpiresByType application/x-shockwave-flash "access 1 month"
    ExpiresByType image/x-icon "access 1 year"
    ExpiresDefault "access 1 month"
</IfModule>
## EXPIRES CACHING ##

<IfModule mod_deflate.c>
    AddOutputFilterByType DEFLATE application/javascript
    AddOutputFilterByType DEFLATE application/rss+xml
    AddOutputFilterByType DEFLATE application/vnd.ms-fontobject
    AddOutputFilterByType DEFLATE application/x-font
    AddOutputFilterByType DEFLATE application/x-font-opentype
    AddOutputFilterByType DEFLATE application/x-font-otf
    AddOutputFilterByType DEFLATE application/x-font-truetype
    AddOutputFilterByType DEFLATE application/x-font-ttf
    AddOutputFilterByType DEFLATE application/x-javascript
    AddOutputFilterByType DEFLATE application/xhtml+xml
    AddOutputFilterByType DEFLATE application/xml
    AddOutputFilterByType DEFLATE font/opentype
    AddOutputFilterByType DEFLATE font/otf
    AddOutputFilterByType DEFLATE font/ttf
    AddOutputFilterByType DEFLATE image/svg+xml
    AddOutputFilterByType DEFLATE image/x-icon
    AddOutputFilterByType DEFLATE text/css
    AddOutputFilterByType DEFLATE text/javascript
    AddOutputFilterByType DEFLATE text/plain
    AddOutputFilterByType DEFLATE text/xml
</IfModule>

RewriteCond %{REQUEST_METHOD} !^(HEAD|OPTIONS|POST|PUT)
RewriteRule .* - [F]

Redirect 301 https://yourwebsite.com/old-page https://yourwebsite.com/new-page

<IfModule mod_headers.c>
    <FilesMatch "\.(ttf|ttc|otf|eot|woff|font.css|css|js|gif|png|jpe?g|svg|svgz|ico|webp)$">
        Header set Access-Control-Allow-Origin "*"
    </FilesMatch>
</IfModule>

<img srcset="image1-730x365.png 730w,
             image1-380x190.png 380w,
             image1-768x384.png 768w,
             image1-1024x512.png 1024w,
             image1-730x365@2x.png 1460w,
             image1-380x190@2x.png 760w"
     sizes="(max-width: 730px) 100vw,
            730px"
     src="image1-730x365.png" width="730" height="365"
<img srcset="image1-730x365.webp 730w,
             image1-380x190.webp 380w,
             image1-768x384.webp 768w,
             image1-1024x512.webp 1024w,
             image1-730x365@2x.webp 1460w,
             image1-380x190@2x.webp 760w"
     sizes="(max-width: 730px) 100vw,
            730px"
     src="image1-730x365.webp" width="730" height="365">
--------------------------------------------------------------------------------------------------------
curl -I https://www.keycdn.com/
curl -o myfile.css https://cdn.keycdn.com/css/animate.min.css
curl -O https://cdn.keycdn.com/css/animate.min.css
curl -H "X-Header: Value" https://www.keycdn.com/
curl -H "X-Header: Value" https://www.keycdn.com/ -v
curl -C - -O https://cdn.keycdn.com/img/cdn-stats.png
curl -D - https://www.keycdn.com/
curl -D - https://www.keycdn.com/ -o /dev/null
curl --limit-rate 200K -O https://cdn.keycdn.com/img/cdn-stats.png
curl -I --http2 https://cdn.keycdn.com/
curl -r 0-20000 -o myfile.png https://cdn.keycdn.com/img/cdn-stats.png
curl --request GET https://www.keycdn.com/
curl -X POST http://www.yourwebsite.com/login/ -d 'username=yourusername&password=yourpassword'
--------------------------------------------------------------------------------------------------------
vi /lightdm/lightdm.conf
allow-guest=false

service lightdm restart
--------------------------------------------------------------------------------------------------------
vi /etc/default/grub
GRUB_RECORDFAIL_TIMEOUT=0

update-grub
--------------------------------------------------------------------------------------------------------
ifconfig | grep inet6
If that produced no output then ipv6 is already disabled. Otherwise first open (as root) the file /etc/modprobe.d/aliases and locate the following line:

alias net-pf-10 ipv6
and replace it with

alias net-pf-10 off
Then open /etc/modprobe.d/blacklist and add the following at the end of the file:

# disable ipv6
blacklist ipv6
Next you'll have to reboot the system since that seems to be the only way to get already loaded ipv6 modules out of memory.

It should be noted that editing only /etc/modprobe.d/blacklist has the same end result of getting ipv6 disabled but a log entry like

modprobe: WARNING: Not loading blacklisted module ipv6
will get added every time something in the system tries to access the net using ipv6. That can happen often in a busy system so there's no point filling log files with it.
--------------------------------------------------------------------------------------------------------
The purpose of this page is to describe how UTF-8 can be disable in Ubuntu / Debian console. At least Ubuntu releases starting from Dapper have UTF-8 enabled by default after a clean install has been done. Checking the current status is simple:

$ echo $LANG
en_US.UTF-8
If the result is anything else than en_US.UTF-8 then UTF-8 shouldn't be enabled and there's no point in reading the rest of this page unless generating locales is the point of interest.

Check /etc/default/locale and /etc/environment as root (so that you can edit it). One of these files will contain line similar to these, LANG is the one you are searching for:

LANG="en_US.UTF-8"
LANGUAGE="en_FI:en"
The LANGUAGE setting depends of what you have selected during the beginning of the install process and usually doesn't nee to be changed. Remove UTF-8 from the LANG setting so that after editing that line will look like:

LANG="en_US"
Save the changes and close the file. Remember to check both files!

Next it's time to generate some new locales because en_US doesn't probably exist yet. Open /var/lib/locales/supported.d/local and if will look like:

en_US.UTF-8 UTF-8
and make it look like:

en_US ISO-8859-1
en_US.UTF-8 UTF-8
Also any other locale that needs to be generated should be added to that file. For example Finnish users might want to have fi_FI ISO-8859-1 in there too. Remeber to save the file after editing.

Now it's time to generate those new locales. As usual, run the following as root.

$ locale-gen
Generating locales...
...
Generation complete.
local-gen will list all locales included in /var/lib/locales/supported.d/local and generate those if necessary. Finally just log out and back in again. UTF-8 should now be disable. That can be checked in the same way we started:

$ echo $LANG
en_US
Ubuntu 12.04 (and possibly also Debian) appendix
(status as of 5.8.2012)
A change done in January 2012 that was introduced in Ubuntu 12.04 causes the file .pam_environment to be created to the user home directory usually when logging in X. The content of that file is created from /etc/default/locale but .UTF-8 is forced after each entry even if the original didn't contain such. This results UTF-8 getting forced even if it has been disabled in /etc/default/locale. The easiest way to fix this is to edit (as root) /usr/share/language-tools/save-to-pam-env and add the following before “exit 0” near the end of the file:

sed -i -e 's:\.UTF-8::g' "$homedir/.pam_environment"
Log out and back in again. Now the .pam_environment shouldn't anymore contain traces of UTF-8.
--------------------------------------------------------------------------------------------------------
#!/bin/bash
 
if [ $# -eq "1" ]; then
        beep -f 3000 -l 50
        for (( ; ; )) ; do
                pin=`ping -c 1 -w 1 "$1" | grep -c "bytes from"`
                if [ $pin -eq 1 ]; then
                        beep -f 3000 -l 50
                        echo "* `date +%H:%M:%S` online!"
                else
                        echo "`date +%H:%M:%S` timeout"
                fi
                sleep 2
        done
else
        echo "Target parameter missing!"
fi
--------------------------------------------------------------------------------------------------------
#!/usr/bin/env python
 
import xml.etree.ElementTree as ET
doc = ET.parse('valgrind.xml')
errors = doc.findall('//error')
 
out = open("cpputest_valgrind.xml","w")
out.write('<?xml version="1.0" encoding="UTF-8"?>\n')
out.write('<testsuite name="valgrind" tests="'+str(len(errors))+'" errors="0" failures="'+str(len(errors))+'" skip="0">\n')
errorcount=0
for error in errors:
    errorcount=errorcount+1
 
    kind = error.find('kind')
    what = error.find('what')
    if  what == None:
        what = error.find('xwhat/text')
 
    stack = error.find('stack')
    frames = stack.findall('frame')
 
    for frame in frames:
        fi = frame.find('file')
        li = frame.find('line')
        if fi != None and li != None:
            break
 
    if fi != None and li != None:
        out.write('    <testcase classname="ValgrindMemoryCheck" name="Memory check '+str(errorcount)+' ('+kind.text+', '+fi.text+':'+li.text+')" time="0">\n')
    else:
        out.write('    <testcase classname="ValgrindMemoryCheck" name="Memory check '+str(errorcount)+' ('+kind.text+')" time="0">\n')
    out.write('        <error type="'+kind.text+'">\n')
    out.write('  '+what.text+'\n\n')
 
    for frame in frames:
        ip = frame.find('ip')
        fn = frame.find('fn')
        fi = frame.find('file')
        li = frame.find('line')
        bodytext = fn.text
        bodytext = bodytext.replace("&","&amp;")
        bodytext = bodytext.replace("<","&lt;")
        bodytext = bodytext.replace(">","&gt;")
        if fi != None and li != None:
            out.write('  '+ip.text+': '+bodytext+' ('+fi.text+':'+li.text+')\n')
        else:
            out.write('  '+ip.text+': '+bodytext+'\n')
 
    out.write('        </error>\n')
    out.write('    </testcase>\n')
out.write('</testsuite>\n')
out.close()
--------------------------------------------------------------------------------------------------------
npm install moment

var moment = require('moment');
moment().format();
--------------------------------------------------------------------------------------------------------
Header unset Etag
FileETag none

FileETag INode MTime Size
--------------------------------------------------------------------------------------------------------
/usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
brew install ffmpeg
ffmpeg -i input.mp4 -profile:v baseline -level 3.0 -s 640x360 -start_number 0 -hls_time 10 -hls_list_size 0 -f hls index.m3u8
--------------------------------------------------------------------------------------------------------
add_header Content-Security-Policy-Report-Only: "default-src 'none'; script-src http://wordpress.keycdn.net";
Header set Content-Security-Policy-Report-Only "default-src 'none'; script-src http://wordpress.keycdn.net;"
<system.webServer>
  <httpProtocol>
    <customHeaders>
      <add name="Content-Security-Policy" value="default-src 'self';" />
    </customHeaders>
  </httpProtocol>
</system.webServer>
--------------------------------------------------------------------------------------------------------
http {
    include /etc/nginx/mime.types;
    charset UTF-8;
    ...
}

AddType 'text/html; charset=UTF-8' html

<meta http-equiv="content-type" content="text/html;charset=UTF-8">
--------------------------------------------------------------------------------------------------------
sudo vi /etc/php5/fpm/php.ini
cgi.fix_pathinfo=0
sudo service php5-fpm restart

server {
    listen 80;
    server_name www.old-website.com;
    return 301 $scheme://www.new-website.com$request_uri;
}

server {
    ...
    rewrite ^(/download/.*)/media/(.*)\..*$ $1/mp3/$2.mp3 last;
    rewrite ^(/download/.*)/audio/(.*)\..*$ $1/mp3/$2.ra last;
    return 403;
    ...
}

if ($http_user_agent ~ MSIE) {
    rewrite ^(.*)$ /msie/$1 break;
}

if ($http_cookie ~* "id=([^;]+)(?:;|$)") {
    set $id $1;
}

if ($request_method = POST) {
    return 405;
}

if ($invalid_referer) {
    return 403;
}
--------------------------------------------------------------------------------------------------------
RewriteCond %{HTTP_HOST} example.com
RewriteRule (.*) http://www.example.com$1

server {
    listen 80;
    server_name example.com;
    return 301 http://www.example.com$request_uri;
}

server {
    listen 80;
    server_name www.example.com;
    # ...
}

location ~ \.php$ {
    if ($http_x_pull ~* "secretkeyname") {
        return 405;
    }
    fastcgi_split_path_info ^(.+\.php)(/.+)$;
    fastcgi_pass unix:/var/run/php5-fpm.sock;
    fastcgi_index index.php;
    include fastcgi_params;
}

RewriteEngine On
RewriteCond %{HTTP:X-Pull} secretkeyname
RewriteRule \.(html|php)$ - [F]

vi nginx.conf
server {
    listen 80 default_server;
    # Define the document root of the server e.g /var/www/html
    root /var/www/html;

    location /nginx_status {
        # Enable Nginx stats
        stub_status on;
        # Only allow access from your IP e.g 1.1.1.1 or localhost #
        allow 127.0.0.1;
        allow 1.1.1.1
        # Other request should be denied
        deny all;
    }
}

<IfModule mod_deflate.c>
    AddOutputFilterByType DEFLATE application/javascript
    AddOutputFilterByType DEFLATE application/rss+xml
    AddOutputFilterByType DEFLATE application/vnd.ms-fontobject
    AddOutputFilterByType DEFLATE application/x-font
    AddOutputFilterByType DEFLATE application/x-font-opentype
    AddOutputFilterByType DEFLATE application/x-font-otf
    AddOutputFilterByType DEFLATE application/x-font-truetype
    AddOutputFilterByType DEFLATE application/x-font-ttf
    AddOutputFilterByType DEFLATE application/x-javascript
    AddOutputFilterByType DEFLATE application/xhtml+xml
    AddOutputFilterByType DEFLATE application/xml
    AddOutputFilterByType DEFLATE font/opentype
    AddOutputFilterByType DEFLATE font/otf
    AddOutputFilterByType DEFLATE font/ttf
    AddOutputFilterByType DEFLATE image/svg+xml
    AddOutputFilterByType DEFLATE image/x-icon
    AddOutputFilterByType DEFLATE text/css
    AddOutputFilterByType DEFLATE text/javascript
    AddOutputFilterByType DEFLATE text/plain
    AddOutputFilterByType DEFLATE text/xml
</IfModule>

gzip on;
gzip_disable "msie6";
gzip_vary on;
gzip_proxied any;
gzip_comp_level 6;
gzip_buffers 16 8k;
gzip_http_version 1.1;
gzip_types application/javascript application/rss+xml application/vnd.ms-fontobject application/x-font application/x-font-opentype application/x-font-otf application/x-font-truetype application/x-font-ttf application/x-javascript application/xhtml+xml application/xml font/opentype font/otf font/ttf image/svg+xml image/x-icon text/css text/javascript text/plain text/xml;
--------------------------------------------------------------------------------------------------------
location ~* \.(png|jpg|jpeg|gif)$ {
    expires 365d;
    add_header Cache-Control "public, no-transform";
}

location ~* \.(js|css|pdf|html|swf)$ {
    expires 30d;
    add_header Cache-Control "public, no-transform";
}

<filesMatch ".(ico|pdf|flv|jpg|jpeg|png|gif|js|css|swf)$">
    Header set Cache-Control "max-age=2592000, public"
</filesMatch>

## EXPIRES CACHING ##
<IfModule mod_expires.c>
    ExpiresActive On
    ExpiresByType image/jpg "access 1 year"
    ExpiresByType image/jpeg "access 1 year"
    ExpiresByType image/gif "access 1 year"
    ExpiresByType image/png "access 1 year"
    ExpiresByType text/css "access 1 month"
    ExpiresByType text/html "access 1 month"
    ExpiresByType application/pdf "access 1 month"
    ExpiresByType text/x-javascript "access 1 month"
    ExpiresByType application/x-shockwave-flash "access 1 month"
    ExpiresByType image/x-icon "access 1 year"
    ExpiresDefault "access 1 month"
</IfModule>
## EXPIRES CACHING ##
--------------------------------------------------------------------------------------------------------
<script>
    (function (i, s, o, g, r, a, m) {
        i['GoogleAnalyticsObject'] = r;
        i[r] = i[r] || function () {
            (i[r].q = i[r].q || []).push(arguments)
        }, i[r].l = 1 * new Date();
        a = s.createElement(o),
            m = s.getElementsByTagName(o)[0];
        a.async = 1;
        a.src = g;
        m.parentNode.insertBefore(a, m)
    })(window, document, 'script', 'https://cdn.yourdomain.com/local-ga.js', 'ga');

    ga('create', 'UA-xxxxxxx-x', 'auto');
    ga('send', 'pageview');
</script>
--------------------------------------------------------------------------------------------------------
function remove_querystring_var($url, $key) {
    $url = preg_replace('/(.*)(?|&)' . $key . '=[^&]+?(&)(.*)/i', '$1$2$4', $url . '&');
    $url = substr($url, 0, -1);
    return ($url);
}
--------------------------------------------------------------------------------------------------------
<filesMatch ".(ico|pdf|flv|jpg|jpeg|png|gif|js|css|swf)$">
    Header set Cache-Control "max-age=84600, public"
</filesMatch>

location ~* \.(js|css|png|jpg|jpeg|gif|ico)$ {
    expires 2d;
    add_header Cache-Control "public, no-transform";
}

header('Last-Modified: ' . gmdate('D, d M Y H:i:s') . ' GMT');
--------------------------------------------------------------------------------------------------------
server {
    set $cache_uri $request_uri;

    # bypass cache if POST requests or URLs with a query string
    if ($request_method = POST) {
        set $cache_uri 'nullcache';
    }

    if ($query_string != "") {
        set $cache_uri 'nullcache';
    }

    # bypass cache if URLs containing the following strings
    if ($request_uri ~* "(/wp-admin/|/xmlrpc.php|/wp-(app|cron|login|register|mail).php|wp-.*.php|/feed/|index.php|wp-comments-popup.php|wp-links-opml.php|wp-locations.php|sitemap(index)?.xml|[a-z0-9-]+-sitemap([0-9]+)?.xml)") {
        set $cache_uri 'nullcache';
    }

    # bypass cache if the cookies containing the following strings
    if ($http_cookie ~* "comment_author|wordpress_[a-f0-9]+|wp-postpass|wordpress_logged_in") {
        set $cache_uri 'nullcache';
    }

    # custom sub directory e.g. /blog
    set $custom_subdir '';

    # default html file
    set $cache_enabler_uri '${custom_subdir}/wp-content/cache/cache-enabler/${http_host}${cache_uri}index.html';

    # webp html file
    if ($http_accept ~* "image/webp") {
        set $cache_enabler_uri '${custom_subdir}/wp-content/cache/cache-enabler/${http_host}${cache_uri}index-webp.html';
    }

    location / {
        gzip_static on; # this directive is not required but recommended
        try_files $cache_enabler_uri $uri $uri/ $custom_subdir/index.php?$args;
    }

    ...
}

# BEGIN Cache Enabler
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteBase /

    # set blog sub path
    SetEnvIf Request_URI "^(.*)$" SUB_PATH=/wp-content/cache/cache-enabler/

    # set Cache Enabler path
    SetEnvIf Request_URI "^(.*)$" CE_PATH=$1

    <IfModule mod_mime.c>
        # webp HTML file
        RewriteCond %{ENV:CE_PATH} /$
        RewriteCond %{ENV:CE_PATH} !^/wp-admin/.*
        RewriteCond %{REQUEST_METHOD} !=POST
        RewriteCond %{QUERY_STRING} =""
        RewriteCond %{HTTP_COOKIE} !(wp-postpass|wordpress_logged_in|comment_author)_
        RewriteCond %{HTTP:Accept-Encoding} gzip
        RewriteCond %{HTTP:Accept} image/webp
        RewriteCond %{DOCUMENT_ROOT}%{ENV:SUB_PATH}%{HTTP_HOST}%{ENV:CE_PATH}index-webp.html.gz -f
        RewriteRule ^(.*) %{ENV:SUB_PATH}%{HTTP_HOST}%{ENV:CE_PATH}index-webp.html.gz [L]

        # gzip HTML file
        RewriteCond %{ENV:CE_PATH} /$
        RewriteCond %{ENV:CE_PATH} !^/wp-admin/.*
        RewriteCond %{REQUEST_METHOD} !=POST
        RewriteCond %{QUERY_STRING} =""
        RewriteCond %{HTTP_COOKIE} !(wp-postpass|wordpress_logged_in|comment_author)_
        RewriteCond %{HTTP:Accept-Encoding} gzip
        RewriteCond %{DOCUMENT_ROOT}%{ENV:SUB_PATH}%{HTTP_HOST}%{ENV:CE_PATH}index.html.gz -f
        RewriteRule ^(.*) %{ENV:SUB_PATH}%{HTTP_HOST}%{ENV:CE_PATH}index.html.gz [L]

        AddType text/html .gz
        AddEncoding gzip .gz
    </IfModule>

    # webp HTML file
    RewriteCond %{ENV:CE_PATH} /$
    RewriteCond %{ENV:CE_PATH} !^/wp-admin/.*
    RewriteCond %{REQUEST_METHOD} !=POST
    RewriteCond %{QUERY_STRING} =""
    RewriteCond %{HTTP_COOKIE} !(wp-postpass|wordpress_logged_in|comment_author)_
    RewriteCond %{HTTP:Accept} image/webp
    RewriteCond %{DOCUMENT_ROOT}%{ENV:SUB_PATH}%{HTTP_HOST}%{ENV:CE_PATH}index-webp.html -f
    RewriteRule ^(.*) %{ENV:SUB_PATH}%{HTTP_HOST}%{ENV:CE_PATH}index-webp.html [L]

    # default HTML file
    RewriteCond %{ENV:CE_PATH} /$
    RewriteCond %{ENV:CE_PATH} !^/wp-admin/.*
    RewriteCond %{REQUEST_METHOD} !=POST
    RewriteCond %{QUERY_STRING} =""
    RewriteCond %{HTTP_COOKIE} !(wp-postpass|wordpress_logged_in|comment_author)_
    RewriteCond %{DOCUMENT_ROOT}%{ENV:SUB_PATH}%{HTTP_HOST}%{ENV:CE_PATH}index.html -f
    RewriteRule ^(.*) %{ENV:SUB_PATH}%{HTTP_HOST}%{ENV:CE_PATH}index.html [L]
</IfModule>
# END Cache Enabler

<filesMatch ".(ico|pdf|flv|jpg|jpeg|png|gif|js|css|swf)$">
    Header set Cache-Control "max-age=84600, public"
</filesMatch>

location ~* \.(js|css|png|jpg|jpeg|gif|ico)$ {
    expires 2d;
    add_header Cache-Control "public, no-transform";
}

header('Cache-Control: max-age=84600');
--------------------------------------------------------------------------------------------------------
sudo apt-get update
sudo apt-get install lsyncd

vi /etc/lsyncd.lua

settings {
    logfile = "/var/log/lsyncd/lsyncd.log",
    statusFile = "/var/log/lsyncd/lsyncd-status.log",
    statusInterval = 20
}

sync {
    default.rsync,
    source="full path to your directory",
    target="username_for_keyCDN@rsync.keycdn.com:YOURZONE/",
    rsync = {
        archive = false,
        acls = false,
        chmod = "D2755,F644"
        compress = true,
        links = false,
        owner = false,
        perms = false,
        verbose = true,
        rsh = "/usr/bin/ssh -p 22 -o StrictHostKeyChecking=no"
    }
}
--------------------------------------------------------------------------------------------------------
sudo apt-get install mtr
yum install mtr
pacman -S mtr
brew install mtr

mtr --report domainx.com
mtr -n --report 8.8.8.8
--------------------------------------------------------------------------------------------------------
Open the rsyslog conf file and add the following lines

vi /etc/rsyslog.conf

# provides UDP syslog reception
module(load="imudp")
Create and open your custom config file.

vi /etc/rsyslog.d/00-custom.conf
# Templates
template(name="ReceiveFormat" type="string" string="%msg:39:$%\n")

# UDP ruleset mapping
input(type="imudp" port="514" ruleset="customRuleset")

# Custom ruleset
ruleset(name="customRuleset") {
    if ($msg contains '366c3df6-93dd-4ec0-a218-aec9d191c59e') then {
        /var/log/cdn.log;ReceiveFormat
        stop
    }
}

service rsyslog restart
netstat -na | grep ":<defined port>"
tcpdump port <defined port>
tail -f /var/log/cdn.log
--------------------------------------------------------------------------------------------------------
echo QUIT | openssl s_client -connect cdn.yourdomain.com:443 -servername cdn.yourdomain.com -tls1 -tlsextdebug -status
echo -n '{path}{secret}{timestamp}' | openssl md5 -binary | openssl base64 | tr +/ -_ | tr -d =
echo -n '/path/to/file1.jpgmysecret1384719072' | openssl md5 -binary | openssl base64 | tr +/ -_ | tr -d =
--------------------------------------------------------------------------------------------------------
var crypto = require('crypto'),
    secret = 'your_secret',
    path = '/path/to/your/file.jpg';

// define expiry (e.g. 120 seconds)
var expire = Math.round(Date.now()/1000) + 120;

// generate md5 token
var md5String = crypto
    .createHash("md5")
    .update(path + secret + expire)
    .digest("binary");

// encode and format md5 token
var token = new Buffer(md5String, 'binary').toString('base64');
token = token.replace(/\+/g, '-').replace(/\//g, '_').replace(/\=/g, '');

// return secure token
console.log('http://demo-1.kxcdn.com' + path + '?token=' + token + '&expire=' + expire);
--------------------------------------------------------------------------------------------------------
require 'digest/md5'
require 'base64'

secret = 'your_secret'
path = '/path/to/your/file.jpg'

# expiry time in seconds (e.g. 3600 seconds)
expire = Time.now.to_i + 3600
token = Base64.encode64(
    Digest::MD5.digest(
        "#{path}#{secret}#{expire}"
    )
).gsub("\n", "").gsub("+", "-").gsub("/", "_").gsub("=", "")

# final secured URL
url = "http://demo-1.kxcdn.com#{path}?token=#{token}&expire=#{expire}"

puts url
--------------------------------------------------------------------------------------------------------
import base64
from hashlib import md5
from time import time

secret = 'your_secret'
path = "/path/to/file1.jpg"

# expiration in seconds (e.g. 180 seconds)
expire = int(time()) + 180

# generate token
token = base64.encodestring(
    md5(
        "%s%s%s" % (path, secret, expire)
    ).digest()
).replace("\n", "").replace("+", "-").replace("/", "_").replace("=", "")
secured_url = "http://demo-1.kxcdn.com%s?token=%s&expire=%s" % (path, token, expire)

# return secured URL
print secured_url
--------------------------------------------------------------------------------------------------------
<?php
    $secret = 'securetokenkey';
    $path = '/path/to/file1.jpg';

    // Expiration in seconds (e.g. 90 seconds)
    $expire = time() + 90;

    // Generate token
    $md5 = md5($path.$secret.$expire, true);

    $md5 = base64_encode($md5);
    $md5 = strtr($md5, '+/', '-_');
    $md5 = str_replace('=', '', $md5);

    // Use this URL
    $url = "http://yourzone-id.kxcdn.com{$path}?token={$md5}&expire={$expire}";

    echo $url;
?>
--------------------------------------------------------------------------------------------------------
kafka-topics.sh --zookeeper <host,host,host> --topic flume-channel --partitions 1 --replication-factor 2 --create
kafka-console-consumer.sh --bootstrap-server <host,host,host> --topic flume-channel --group flume-channel-consumers --from-beginning
--------------------------------------------------------------------------------------------------------
docker run -p "25:25" -p "143:143" linagora/james-jpa-sample:3.3.0
--------------------------------------------------------------------------------------------------------
DISM /Online /Cleanup-Image /RestoreHealth
Get-AppxPackage -AllUsers| Foreach {Add-AppxPackage -DisableDevelopmentMode -Register “$($_.InstallLocation)\AppXManifest.xml”}
--------------------------------------------------------------------------------------------------------
cmd.exe /k echo WELCOME
--------------------------------------------------------------------------------------------------------git clone https://github.com/armdev/springboot2-swagger.git
cd springboot2-swagger.git
mvn spring-boot:run -P update-sourcepath-for-lombok
firefox localhost:4545/swagger-ui.html
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
#### Database
--------------------------------------------------------------------------------------------------------
"c:\xampp\mysql\bin\mysqld.exe" --defaults-file="c:\xampp\mysql\bin\my.ini" --standalone --console
--------------------------------------------------------------------------------------------------------
CREATE ROLE ivs NOINHERIT NOREPLICATION LOGIN PASSWORD 'user_ivs';
--------------------------------------------------------------------------------------------------------
UPDATE SET date_from=now() AT TIME ZONE 'GMT'
date_from timestamp without time zone
SELECT date_from AT TIME ZONE 'GMT'
--------------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS templates (
  id UUID PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  content BYTEA NOT NULL
);

CREATE TABLE IF NOT EXISTS images (
  id UUID PRIMARY KEY,
  template_id UUID,
  name VARCHAR(255),
  content BYTEA NOT NULL,
  foreign key (template_id) references templates on delete cascade
);

create or replace function bytea_import(p_path text, p_result out bytea)
                   language plpgsql as $$
declare
  l_oid oid;
begin
  select lo_import(p_path) into l_oid;
  select lo_get(l_oid) INTO p_result;
  perform lo_unlink(l_oid);
end;$$;
--------------------------------------------------------------------------------------------------------
create database activiti
CHARACTER SET utf8
COLLATE utf8_bin;

create database activitiadmin
CHARACTER SET utf8
COLLATE utf8_bin;
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
#### Maven & Gradle
--------------------------------------------------------------------------------------------------------
mvn clean install -DskipTest
cd core
mvn liquibase:update
--------------------------------------------------------------------------------------------------------
mvn clean test -pl streamflyer-core jacoco:report coveralls:report -Pcoverage
mvn clean dependency:copy-dependencies package
mvn site
mvn license:format
--------------------------------------------------------------------------------------------------------
mvn enforcer:display-info
mvn enforcer:enforce
--------------------------------------------------------------------------------------------------------
$ mvn archetype:generate -DgroupId=com.example
 -DartifactId=demo
 -DarchetypeArtifactId=maven-archetype-webapp
 -DinteractiveMode=false
--------------------------------------------------------------------------------------------------------
mvn verify cargo:run
docker-compose up mongodb
mvn spring-boot:run
--------------------------------------------------------------------------------------------------------
gradlew clean build publishToMavenLocal -i -x test
--------------------------------------------------------------------------------------------------------
gradle dependencies
mvn dependency:tree
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
#### RabbitMQ
--------------------------------------------------------------------------------------------------------
# sbin/rabbitmqctl stop
rabbitmqctl list_permissions --vhost gw1
rabbitmqctl list_permissions --vhost /
# sbin/rabbitmq-server -detached

http://localhost:15672/
# sbin/rabbitmq-plugins enable rabbitmq_management
sbin/rabbitmqctl status
sbin/rabbitmqctl stop
chkconfig --list | grep -i qpid
chkconfig qpidd off
chkconfig --list | grep -i qpid

cd /usr/save
wget http://www.rabbitmq.com/releases/rabbitmq-server/v3.0.4/rabbitmq-server-generic-unix-3.0.4.tar.gz
tar xvfz rabbitmq-server-generic-unix-3.0.4.tar.gz
cd rabbitmq_server-3.0.4

# cd /usr/save/rabbitmq_server-3.0.4
# sbin/rabbitmq-server -detached
--------------------------------------------------------------------------------------------------------
rabbitmqctl add_user userivs ivs
rabbitmqctl set_user_tags userivs administrator
rabbitmqctl set_permissions -p / userivs ".*" ".*" ".*"
rabbitmq-plugins enable rabbitmq_management

## Get a list of vhosts:
curl -i -u userivs:ivs http://localhost:15672/api/whoami
## Get a list of channels, fast publishers first, restricting the info items we get back:
curl -i -u guest:guest http://localhost:15672/api/vhosts
## Create a new vhost:
curl -i -u guest:guest "http://localhost:15672/api/channels?sort=message_stats.publish_details.rate&sort_reverse=true&columns=name,message_stats.publish_details.rate,message_stats.deliver_get_details.rate"
# Create a new exchange in the default virtual host:
curl -i -u guest:guest -H "content-type:application/json" -XPUT http://localhost:15672/api/vhosts/foo
## Delete exchange again:
curl -i -u guest:guest -H "content-type:application/json" -XDELETE http://localhost:15672/api/exchanges/%2F/my-new-exchange

sbin/rabbitmqctl stop
sbin/rabbitmq-server -detached
# sbin/rabbitmqctl status
--------------------------------------------------------------------------------------------------------
%comspec% /k "C:\Program Files\RabbitMQ Server\rabbitmq_server-3.7.14\sbin\rabbitmq-service.bat" start & if not errorlevel 1 exit /b 0
%comspec% /k "C:\Program Files\RabbitMQ Server\rabbitmq_server-3.7.14\sbin\rabbitmq-service.bat" stop & if not errorlevel 1 exit /b 0
%comspec% /k "C:\Program Files\RabbitMQ Server\rabbitmq_server-3.7.14\sbin\rabbitmq-service.bat" remove & if not errorlevel 1 exit /b 0
%comspec% /k "C:\Program Files\RabbitMQ Server\rabbitmq_server-3.7.14\sbin\rabbitmq-service.bat" install & if not errorlevel 1 exit /b 0
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------


