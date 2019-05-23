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
curl -X GET "http://vdlg-pba11-auth-1.pba.internal:5000/api/internal/v1/users/alexander.rogalskiy%40paragon-software.com" -H "accept: text/plain"
--------------------------------------------------------------------------------------------------------
Note: Should you find difficulties connecting to the WebDAV directory, update the Basic Authentication Level in Windows Registry.

1. Right-click Start and select Run.

2. Type regedit and press Enter to open Windows Registry Editor.

3. Go to the directory path: “HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WebClient\Parameters.”

Map Webdav Drive Windows 10 Registry Editor Parameters Basic Auth Level

4. Find “BasicAuthLevel” value. By default the value is set at 2, but if it’s not, right-click and select Modify and then change to 2.
--------------------------------------------------------------------------------------------------------
sudo apt install flatpak
sudo flatpak remote-add --if-not-exists flathubhttps://dl.flathub.org/repo/flathub.flatpakrepo
sudo flatpak remote-add --if-not-exists winepak https://dl.winepak.org/repo/winepak.flatpakrepo
flatpak search overwatch
sudo flatpak install winepak com.blizzard.Overwatch
--------------------------------------------------------------------------------------------------------
ip a | grep inet
--------------------------------------------------------------------------------------------------------
spring:
  profiles:
    include: regex
  autoconfigure:
    exclude:
      - org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration
      - org.springframework.boot.autoconfigure.data.redis.RedisRepositoriesAutoConfiguration
--------------------------------------------------------------------------------------------------------
timedatectl set-ntp true
cfdisk

mkfs.ext4 /dev/sda1
mkfs.ext4 /dev/sda2

mount /dev/sda2 /mnt
mkidr /mnt/boot
mount /dev/sda1 /mnt/boot

pacstrap /mnt base

genfstab -U /mnt >> /mnt/etc/fstab
arch-chroot /mnt

ln -sf /usr/share/zoneinfo/America/New_York /etc/localtime

hwclock --systohc

locale-gen
vi /etc/locale.conf
LANG=en_US.UTF-8

systemctl enable dhcpcd
useradd -m -G users,audio,input,optical,storage,video -s /bin/bash username

mkinitcpio -p linux
pacman -S grub
grub-install --target=i386-pc /dev/sda
grub-mkconfig -o /boot/grub/grub.cfg

exit
umount -R /mnt
reboot
--------------------------------------------------------------------------------------------------------
var paragraphs = document.getElementsByTagName("p");
for (var i = 0; i < paragraphs.length; i++) {
  var paragraph = paragraphs.item(i);
  paragraph.style.setProperty("color", "blue", null);
}

d3.selectAll("p").style("color", "blue");
--------------------------------------------------------------------------------------------------------
@Pattern(regexp="[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", message="Invalid email")//if the field contains email address consider using this annotation to enforce field validation
--------------------------------------------------------------------------------------------------------
Install-Package Umbraco.Iconator
--------------------------------------------------------------------------------------------------------
sudo do-release-upgrade -d
sudo do-release-upgrade

sudo apt install update-manager-core
sudo apt update && sudo apt upgrade

sudo nano /etc/update-manager/release-upgrades
Change Prompt=lts to Prompt=normal. Press Ctrl + X, then y followed by Enter to save the file.

sudo systemctl reboot
sudo reboot
--------------------------------------------------------------------------------------------------------
conda install -c quantnet qnt
conda install package-name=2.3.4
conda install /package-path/package-filename.tar.bz2
conda install /packages-path/packages-filename.tar
--------------------------------------------------------------------------------------------------------
<html>
  <svg
    width="5cm"
    height="4cm"
    version="1.1"
    xmlns="http://www.w3.org/2000/svg"
    xmlns:xlink="http://www.w3.org/1999/xlink"
  >
    <path d="M 0 0 L 100 0 L 100 100 L 0 50 Z" />
  </svg>
</html>
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
git reset --hard @{u}
git branch -a; git tag, git log --all or, my preference, you can look graphically at gitk --all --date-order
git reset --hard REF
git reset --hard HEAD^

git branch nonce $last
git rebase -p --onto $destination $first^ nonce

git checkout $destination
git reset --hard nonce
git branch -d nonce


gitk --all --date-order
git rebase -p --onto $first^ $last $source
git rebase -p --onto SHA^ SHA

https://sethrobertson.github.io/GitFixUm/fixup.html

bfg --strip-blobs-bigger-than 100M --replace-text banned.txt repo.git

git clone --mirror git://example.com/some-big-repo.git
java -jar bfg.jar --strip-blobs-bigger-than 100M some-big-repo.git
$ cd some-big-repo.git
$ git reflog expire --expire=now --all && git gc --prune=now --aggressive
git push

$ bfg --delete-files id_{dsa,rsa}  my-repo.git
$ bfg --strip-blobs-bigger-than 50M  my-repo.git
$ bfg --replace-text passwords.txt  my-repo.git
$ bfg --delete-folders .git --delete-files .git  --no-blob-protection  my-repo.git
$ bfg --strip-biggest-blobs 100 --protect-blobs-from master,maint,next repo.git
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
#!/bin/bash

# ======================================
# ANSI
# ======================================
ansi_reset='\e[0m'

blue='\e[34m'

yellow_b='\e[1;33m'

red_b='\e[1;31m'


# ======================================
# Constants
# ======================================
svg_source="icons.svg"

svg_src_tmp="/tmp/icons.svg"

default_color="#4078c0"

default_size=32

icon_index="index.txt"


# ======================================
# User Input
# ======================================
echo "Enter icon size (skip for default icon dimensions): "
read -r icon_size

echo "Enter 1 or more colors (space or tab separated): "
read -r -a icon_color


# ======================================
# Checks
# ======================================
# If no colors given, add default color to array
[ ${#icon_color[*]} -eq 0 ] && icon_color[0]=$default_color

icon_size=${icon_size:-"$default_size"}


# ======================================
# RENDER
# ======================================
for color in ${icon_color[*]}; do

    mkdir -p "${color}__$icon_size"


    trap 'rm $svg_src_tmp; exit' INT TERM


    cp "$svg_source" "$svg_src_tmp"


    # Change color of temp copy
    [ ! "$color" = "$default_color" ] &&
    sed -i "s/$default_color/$color/" "$svg_src_tmp"


    # Loop through index.txt & render png's
    while read -r i; do

        if [ -f "${color}__$icon_size/$i.png" ]; then
            echo -e "${red_b}${color}__$icon_size/$i.png exists.${ansi_reset}"

        else
            echo
            echo -e "${blue}Rendering ${yellow_b}${color}__$icon_size/$i.png${ansi_reset}"
            inkscape --export-id="${i}" \
                     --export-id-only \
                     --export-width="$icon_size" --export-height="$icon_size" \
                     --export-png="${color}__$icon_size/$i.png" "$svg_src_tmp" >/dev/null
        fi
    done < "$icon_index"


    # Remove copy before next iteration or EXIT
    rm "$svg_src_tmp"

done


# If notify-send installed, send notif
hash notify-send 2>/dev/null &&
notify-send -i 'terminal' \
            -a 'Terminal' \
            'Terminal'    \
            'Finished rendering icons!'
--------------------------------------------------------------------------------------------------------
sudo apt install oracle-java11-set-default
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
mvn license:update-file-header
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
#### DEVELOPMENT
--------------------------------------------------------------------------------------------------------
public class CacheManager {
    public static final List<CacheManager> ALL_CACHE_MANAGERS = new CopyOnWriteArrayList<CacheManager>();
....
}
--------------------------------------------------------------------------------------------------------
@CacheConfig(cacheNames="book", keyGenerator="myKeyGenerator") 
public class BookRepository {

    @Cacheable
    public Book findBook(ISBN isbn) {...}

    public Book thisIsNotCached(String someArg) {...}
}
--------------------------------------------------------------------------------------------------------
public class CacheUtil {
  public static CacheManager myCacheManager;

  public CacheManager getMyCacheManager() {
    if(myCacheManager == null) {
    for (CacheManager cacheManager : CacheManager.ALL_CACHE_MANAGERS) {
       if("myCacheManager".equals(cacheManager.getName())) {
          myCacheManager = cacheManager;
       }
    }
    return myCacheManager;
  }
}
--------------------------------------------------------------------------------------------------------
var cacheManager = require('cache-manager');
var fsStore = require('cache-manager-fs');
var diskCache = cacheManager.caching({
    store: fsStore, options: {
      ttl: 60*60,
      maxsize: 1000*1000*1000,
      path: 'diskcache',
      preventfill: true
    }
  });

var ttl = 30;

function getUser(id, cb) {
    setTimeout(function () {
        console.log("Returning user from slow database.");
        cb(null, {id: id, name: 'Bob'});
    }, 5000);
}

var userId = 123;
var key = 'user_' + userId;

// Note: ttl is optional in wrap()
memoryCache.wrap(key, function (cb) {
    getUser(userId, cb);
}, {ttl: ttl}, function (err, user) {
    console.log(user);

    // Second time fetches user from memoryCache
    memoryCache.wrap(key, function (cb) {
        getUser(userId, cb);
    }, function (err, user) {
        console.log(user);
    });
});
--------------------------------------------------------------------------------------------------------
@Bean
public CacheManager cacheManager() {
	SimpleCacheManager cacheManager = new SimpleCacheManager();
	cacheManager.setCaches( Collections.singletonList( new ConcurrentMapCache( “userCache” ) ) );

	// manually call initialize the caches as our SimpleCacheManager is not declared as a bean
	cacheManager.initializeCaches(); 

	return new TransactionAwareCacheManagerProxy( cacheManager );
}
--------------------------------------------------------------------------------------------------------
Cache transactionAwareUserCache( CacheManager cacheManager ) {
	return new TransactionAwareCacheDecorator( cacheManager.getCache( “userCache” ) );
}
--------------------------------------------------------------------------------------------------------
@Bean
public CacheManager cacheManager( net.sf.ehcache.CacheManager ehCacheCacheManager ) {
	EhCacheCacheManager cacheManager = new EhCacheCacheManager();
	cacheManager.setCacheManager( ehCacheCacheManager );
	cacheManager.setTransactionAware( true );
	return cacheManager;
}

--------------------------------------------------------------------------------------------------------
class UserService {
	@Cacheable(value = "userCache", unless = "#result != null")
	public User getUserById( long id ) {
   		return userRepository.getById( id );
	}
}
 
class UserRepository {
	@Caching(
      put = {
            @CachePut(value = "userCache", key = "'username:' + #result.username", condition = "#result != null"),
            @CachePut(value = "userCache", key = "#result.id", condition = "#result != null")
      }
	)
	@Transactional(readOnly = true)
	public User getById( long id ) {
	   ...
	}
}
--------------------------------------------------------------------------------------------------------
    /**
     * Default parsing patterns
     */
    private static final String UPPER = "\\p{Lu}|\\P{InBASIC_LATIN}";
    private static final String LOWER = "\\p{Ll}";
    private static final String CAMEL_CASE_REGEX = "(?<!(^|[%u_$]))(?=[%u])|(?<!^)(?=[%u][%l])".replace("%u", UPPER).replace("%l", LOWER);
    /**
     * Default camel case {@link Pattern}
     */
    private static final Pattern CAMEL_CASE = Pattern.compile(CAMEL_CASE_REGEX);
	
	    /**
     * Returns {@link List} by input source {@link String} and 
     * @param source
     * @param toLower
     * @return
     */
    private static List<String> split(final String source, final boolean toLower) {
        Objects.requireNonNull(source, "Source string must not be null!");
        final List<String> result = CAMEL_CASE.splitAsStream(source).map(i -> toLower ? i.toLowerCase() : i).collect(Collectors.toList());
        return Collections.unmodifiableList(result);
    }
--------------------------------------------------------------------------------------------------------
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.concurrent.ConcurrentMapCache;
import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
import org.springframework.cache.support.SimpleCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static java.util.Arrays.asList;

@Configuration
@EnableCaching
public class MailCacheConfiguration {

    /**
     * Default mail cache names
     */
    public static final String DEFAULT_MAIL_FOLDER_CACHE = "MAIL_FOLDER_CACHE";
    public static final String DEFAULT_MAIL_STORE_CACHE = "MAIL_STORE_CACHE";

//    @Bean
//    public CacheManager cacheManager() {
//        final SimpleCacheManager cacheManager = new SimpleCacheManager();
//        cacheManager.setCaches(asList(this.mailFolderCache(), this.mailStoreCache()));
//        cacheManager.afterPropertiesSet();
//        return cacheManager;
//    }

    @Bean
    public CacheManager cacheManager() {
        final ConcurrentMapCacheManager cacheManager = new ConcurrentMapCacheManager("addresses");
        cacheManager.setAllowNullValues(false);
        cacheManager.setCacheNames(asList(DEFAULT_MAIL_FOLDER_CACHE, DEFAULT_MAIL_STORE_CACHE));
        return cacheManager;
    }

    @Bean
    public Cache mailFolderCache() {
        return new ConcurrentMapCache(DEFAULT_MAIL_FOLDER_CACHE);
    }

    @Bean
    public Cache mailStoreCache() {
        return new ConcurrentMapCache(DEFAULT_MAIL_STORE_CACHE);
    }
}
--------------------------------------------------------------------------------------------------------
@CacheEvict(value = {DEFAULT_MAIL_FOLDER_CACHE, DEFAULT_MAIL_STORE_CACHE}, allEntries = true)
public void destroy() {
}
	
@Caching(evict = { 
  @CacheEvict("addresses"), 
  @CacheEvict(value="directory", key="#customer.name") })
public String getAddress(Customer customer) {...}
--------------------------------------------------------------------------------------------------------
spring:
  # (DataSourceAutoConfiguration & DataSourceProperties)
  datasource:
    name: ds-h2
    url: jdbc:h2:D:/work/workspace/fdata;DATABASE_TO_UPPER=false
    username: h2
    password: h2
    driver-class: org.h2.Driver
	
@Configuration
@Component
public class DataSourceBean {

    @ConfigurationProperties(prefix = "spring.datasource")
    @Bean
    @Primary
    public DataSource getDataSource() {
        return DataSourceBuilder
                .create()
//                .url("jdbc:h2:D:/work/workspace/fork/gs-serving-web-content/initial/data/fdata;DATABASE_TO_UPPER=false")
//                .username("h2")
//                .password("h2")
//                .driverClassName("org.h2.Driver")
                .build();
    }
}
--------------------------------------------------------------------------------------------------------
https://<API key>@api.keycdn.com/zones/purge/<zone id>.json
--------------------------------------------------------------------------------------------------------
import org.springframework.boot.Banner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.ComponentScan;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

@SpringBootApplication
@EnableAutoConfiguration
@EnableSwagger2
@ComponentScan(basePackages = {"io.project"})
@EntityScan("io.project.domain")
public class Application {

    public static void main(String[] args) {
        final SpringApplication application = new SpringApplication(Application.class);
        application.setBannerMode(Banner.Mode.OFF);
        application.setWebApplicationType(WebApplicationType.SERVLET);
        application.run(args);
    }
}
--------------------------------------------------------------------------------------------------------
#!/bin/bash

###
# #%L
# che-starter
# %%
# Copyright (C) 2017 Red Hat, Inc.
# %%
# All rights reserved. This program and the accompanying materials
# are made available under the terms of the Eclipse Public License v1.0
# which accompanies this distribution, and is available at
# http://www.eclipse.org/legal/epl-v10.html
# #L%
###

echo "Installing certificate into $CHE_STARTER_HOME/InstallCert/ directory"

# Import the certificate
cd $CHE_STARTER_HOME/InstallCert/

echo "Import the remote certificate from ${OSO_ADDRESS}"
java InstallCert $OSO_ADDRESS << ANSWERS
1
ANSWERS

echo "Export the certificate into the keystore for ${OSO_DOMAIN_NAME}"
keytool -exportcert -alias $OSO_DOMAIN_NAME-1 -keystore jssecacerts -storepass changeit -file $KUBERNETES_CERTS_CA_FILE

cd $CHE_STARTER_HOME/


exec java -Djava.security.egd=file:/dev/./urandom -jar ${CHE_STARTER_HOME}/app.jar $@
exit $?
--------------------------------------------------------------------------------------------------------
public static void main(String[] args) {
  Optional<Integer> maxAge = employeeList
      .stream()
      .collect(Collectors.mapping((Employee emp) -> emp.getAge(), Collectors.maxBy(Integer::compareTo)));
  System.out.println("Max Age: " + maxAge.get());
}
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
### VIM
--------------------------------------------------------------------------------------------------------
Global

:help keyword – open help for keyword
:o file – open file
:saveas file – save file as
:close – close current window

Cursor Movements

h – move cursor left
j – move cursor down
k – move cursor up
l – move cursor right
H – move to top of screen
M – move to middle of screen
L – move to bottom of screen
w – jump forwards to the start of a word
W – jump forwards to the start of a word (words can contain punctuation)
e – jump forwards to the end of a word
E – jump forwards to the end of a word (words can contain punctuation)
b – jump backwards to the start of a word
B – jump backwards to the start of a word (words can contain punctuation)
0 – jump to the start of the line
^ – jump to the first non-blank character of the line
$ – jump to the end of the line
g_ – jump to the last non-blank character of the line
gg – go to the first line of the document
G – go to the last line of the document
5G – go to line 5
fx – jump to next occurrence of character x
tx – jump to before next occurrence of character x
} – jump to next paragraph (or function/block, when editing code)
{ – jump to previous paragraph (or function/block, when editing code)
zz – center cursor on screen
Ctrl + b – move back one full screen
Ctrl + f – move forward one full screen
Ctrl + d – move forward 1/2 a screen
Ctrl + u – move back 1/2 a screen

Tip: Prefix a cursor movement command with a number to repeat it. For example, 4j moves down 4 lines.

Insert Mode

i – insert before the cursor
I – insert at the beginning of the line
a – insert (append) after the cursor
A – insert (append) at the end of the line
o – append (open) a new line below the current line
O – append (open) a new line above the current line
ea – insert (append) at the end of the word
Esc – exit insert mode

Editing

r – replace a single character
J – join line below to the current line
cc – change (replace) entire line
cw – change (replace) to the end of the word
c$ – change (replace) to the end of the line
s – delete character and substitute text
S – delete line and substitute text (same as cc)
xp – transpose two letters (delete and paste)
u – undo
Ctrl + r – redo
. – repeat last command

Marking Text (Visual Mode)

v – start visual mode, mark lines, then perform an operation (such as d-delete)
V – start linewise visual mode
Ctrl + v – start blockwise visual mode
o – move to the other end of marked area
O – move to other corner of block
aw – mark a word
ab – a block with ()
aB – a block with {}
ib – inner block with ()
iB – inner block with {}
Esc – exit visual mode

Visual Commands

> – shift text right
< – shift text left
y – yank (copy) marked text
d – delete marked text
~ – switch case

Registers

:reg – show registers content
"xy – yank into register x
"xp – paste contents of register x

Tip: Registers are being stored in ~/.viminfo, and will be loaded again on next restart of vim.

Tip: Register 0 contains always the value of the last yank command.

Marks

:marks – list of marks
ma – set current position for mark A
`a – jump to position of mark A
y`a – yank text to position of mark A

Macros

qa – record macro a
q – stop recording macro
@a – run macro a
@@ – rerun last run macro

Cut and Paste

yy – yank (copy) a line
2yy – yank (copy) 2 lines
yw – yank (copy) the characters of the word from the cursor position to the start of the next word
y$ – yank (copy) to end of line
p – put (paste) the clipboard after cursor
P – put (paste) before cursor
dd – delete (cut) a line
2dd – delete (cut) 2 lines
dw – delete (cut) the characters of the word from the cursor position to the start of the next word
D – delete (cut) to the end of the line
d$ – delete (cut) to the end of the line
x – delete (cut) character

Exiting

:w – write (save) the file, but don’t exit
:w !sudo tee % – write out the current file using sudo
:wq or :x or ZZ – write (save) and quit
:q – quit (fails if there are unsaved changes)
:q! or ZQ – quit and throw away unsaved changes

Search and Replace

/pattern – search for pattern
?pattern – search backward for pattern
\vpattern – ‘very magic’ pattern: non-alphanumeric characters are interpreted as special regex symbols (no escaping needed)
n – repeat search in same direction
N – repeat search in opposite direction
:%s/old/new/g – replace all old with new throughout file
:%s/old/new/gc – replace all old with new throughout file with confirmations
:noh – remove highlighting of search matches

Search in Multiple Files

:vimgrep /pattern/ {file} – search for pattern in multiple files
e.g.
:vimgrep /foo/ **/*
:cn – jump to the next match
:cp – jump to the previous match
:copen – open a window containing the list of matches

Working With Multiple Files

:e file – edit a file in a new buffer
:bnext or :bn – go to the next buffer
:bprev or :bp – go to the previous buffer
:bd – delete a buffer (close a file)
:ls – list all open buffers
:sp file – open a file in a new buffer and split window
:vsp file – open a file in a new buffer and vertically split window
Ctrl + ws – split window
Ctrl + ww – switch windows
Ctrl + wq – quit a window
Ctrl + wv – split window vertically
Ctrl + wh – move cursor to the left window (vertical split)
Ctrl + wl – move cursor to the right window (vertical split)
Ctrl + wj – move cursor to the window below (horizontal split)
Ctrl + wk – move cursor to the window above (horizontal split)

Tabs

:tabnew or :tabnew file – open a file in a new tab
Ctrl + wT – move the current split window into its own tab
gt or :tabnext or :tabn – move to the next tab
gT or :tabprev or :tabp – move to the previous tab
#gt – move to tab number #
:tabmove # – move current tab to the #th position (indexed from 0)
:tabclose or :tabc – close the current tab and all its windows
:tabonly or :tabo – close all tabs except for the current one
:tabdo command – run the command on all tabs (e.g. :tabdo q – closes all opened tabs)
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
### INFO
--------------------------------------------------------------------------------------------------------
Deploy an Open Source Application

Find an application that you would be interested in using and deploy it. Even if you don’t end up using the application you’ll have gained the experience of setting it up.

    Alfresco
    Bugzilla
    DokuWiki
    Drupal
    Etherpad Lite
    Gitlab
    Joomla
    MediaWiki
    Moodle
    osTicket
    OwnCloud
    phpBB
    PunBB
    Redmine
    ServiceDesk Plus
    SugarCRM
    Trac
    Twiki
    WordPress
    Zen Cart

Configure Common Services – Client AND Server

    cron
    CUPS
    DHCP
    DNS
    Email (SMTP, POP, IMAP)
    LDAP
    NFS
    NIS
    NTP
    SSH

Configure Monitoring

    Cacti
    Icinga
    Monit
    Munin
    Nagios
    OpenNMS
    Zabbix
    Zenoss

Create a Build System

    Cobbler
    FAI
    Foreman
    Kickstart
    Razor
    Spacewalk

Create a Centralized Syslog Server

    ELK Stack: Elasticsearch, Logstash & Kibana
    Fluentd
    Logstash
    Kibana
    Splunk
    syslog-ng

System Automation

    Ansible
    Chef
    MakeFiles and/or RakeFiles
    Puppet
    Salt Stack
    Write Shell Scripts

Cluster All The Things

    Load balance web servers or other services using HAProxy
    Create a MySQL Cluster
    Create a GlusterFS Cluster
    Red Hat Cluster (Conga)

Build a NAS

    NFS
    Samba

Practice Migrating Data

    Migrate data from a disk on one server to a disk on another server.
    Migrate Databases.
        Live migrations
        Export / Import

Create and Manage Users

    FreeIPA
    LDAP
    NIS
    User name ideas: http://www.fakenamegenerator.com/

Configure a Backup Server

    Amanda
    Bacula
    Rsnapshot
    Rsync + SSH

Configure a Firewall

    IPtables
    UFW

Learn LVM

    Create and restore snapshots
    Extend volumes without downtime

Configure a Proxy Server

    Forward Proxy
        Apache
        Squid
    Reverse Proxy
        Apache
        NGINX
        Pound

Learn Revision Control

    CVS
    Git
    RCS
--------------------------------------------------------------------------------------------------------
### UNIX/LINUX
--------------------------------------------------------------------------------------------------------
arping
	

Send ARP request to a neighbour host

arping -I eth0 192.168.1.1

Send ARP request to 192.168.1.1 via interface eth0

arping -D -I eth0 192.168.1.1

Check for duplicate MAC addresses at 192.168.1.1 on eth0
--------------------------------------------------------------------------------------------------------
ethtool
	

Query or control network driver and hardware settings

ethtool -g eth0

Display ring buffer for eth0

ethtool -i eth0

Display driver information for eth0

ethtool -p eth0

Identify eth0 by sight, typically by causing LEDs to blink on the network port

ethtool -S eth0

Display network and driver statistics for eth0
--------------------------------------------------------------------------------------------------------
ss
	

Display socket statistics. The below options can be combined

ss -a

Show all sockets (listening and non-listening)

ss -e

Show detailed socket information

ss -o

Show timer information

ss -n

Do not resolve addresses

ss -p

Show process using the socket
--------------------------------------------------------------------------------------------------------
arp -a = ip neigh
arp -v = ip -s neigh
arp -s 192.168.1.1 1:2:3:4:5:6 = ip neigh add 192.168.1.1 lladdr 1:2:3:4:5:6 dev eth1
arp -i eth1 -d 192.168.1.1 = ip neigh del 192.168.1.1 dev eth1
ifconfig -a = ip addr
ifconfig eth0 down = ip link set eth0 down
ifconfig eth0 up = ip link set eth0 up
ifconfig eth0 192.168.1.1 = ip addr add 192.168.1.1/24 dev eth0
ifconfig eth0 netmask 255.255.255.0 = ip addr add 192.168.1.1/24 dev eth0
ifconfig eth0 mtu 9000 = ip link set eth0 mtu 9000
ifconfig eth0:0 192.168.1.2 = ip addr add 192.168.1.2/24 dev eth0
netstat = ss
netstat -neopa = ss -neopa
netstat -g = ip maddr
route = ip route
route add -net 192.168.1.0 netmask 255.255.255.0 dev eth0 = ip route add 192.168.1.0/24 dev eth0
route add default gw 192.168.1.1 = ip route add default via 192.168.1.1
--------------------------------------------------------------------------------------------------------
neigh add
	

Add an entry to the ARP Table

ip neigh add 192.168.1.1 lladdr 1:2:3:4:5:6 dev em1

Add address 192.168.1.1 with MAC 1:2:3:4:5:6 to em1
--------------------------------------------------------------------------------------------------------
neigh del
	

Invalidate an entry

ip neigh del 192.168.1.1 dev em1

Invalidate the entry for 192.168.1.1 on em1
--------------------------------------------------------------------------------------------------------
neigh replace
	

Replace, or adds if not defined, an entry to the ARP table

ip neigh replace 192.168.1.1 lladdr 1:2:3:4:5:6 dev em1

Replace the entry for address 192.168.1.1 to use MAC 1:2:3:4:5:6 on em1
--------------------------------------------------------------------------------------------------------
route add
	

Add an entry to the routing table

ip route add default via 192.168.1.1 dev em1

Add a default route (for all addresses) via the local gateway 192.168.1.1 that can be reached on device em1

ip route add 192.168.1.0/24 via 192.168.1.1

Add a route to 192.168.1.0/24 via the gateway at 192.168.1.1

ip route add 192.168.1.0/24 dev em1

Add a route to 192.168.1.0/24 that can be reached on

device em1
--------------------------------------------------------------------------------------------------------
route delete
	

Delete a routing table entry

ip route delete 192.168.1.0/24 via 192.168.1.1

Delete the route for 192.168.1.0/24 via the gateway at 192.168.1.1
--------------------------------------------------------------------------------------------------------
route replace
	

Replace, or add if not defined, a route

ip route replace 192.168.1.0/24 dev em1

Replace the defined route for 192.168.1.0/24 to use

device em1
--------------------------------------------------------------------------------------------------------
route get
	

Display the route an address will take

ip route get 192.168.1.5

Display the route taken for IP 192.168.1.5
--------------------------------------------------------------------------------------------------------
addr add
	

Add an address

ip addr add 192.168.1.1/24 dev em1

Add address 192.168.1.1 with netmask 24 to device em1
--------------------------------------------------------------------------------------------------------
addr del
	

Delete an address

ip addr del 192.168.1.1/24 dev em1

Remove address 192.168.1.1/24 from device em1
--------------------------------------------------------------------------------------------------------
link set
	

Alter the status of the interface

ip link set em1 up

Bring em1 online

ip link set em1 down

Bring em1 offline

ip link set em1 mtu 9000

Set the MTU on em1 to 9000

ip link set em1 promisc on

Enable promiscuous mode for em1
--------------------------------------------------------------------------------------------------------
maddr add
	

Add a static link-layer multicast address

ip maddr add 33:33:00:00:00:01 dev em1

Add mutlicast address 33:33:00:00:00:01 to em1
--------------------------------------------------------------------------------------------------------
maddr del
	

Delete a multicast address

ip maddr del 33:33:00:00:00:01 dev em1

Delete address 33:33:00:00:00:01 from em1
--------------------------------------------------------------------------------------------------------
addr
	

Display IP Addresses and property information (abbreviation of address)

ip addr

Show information for all addresses

ip addr show dev em1

Display information only for device em1
--------------------------------------------------------------------------------------------------------
link
	

Manage and display the state of all network interfaces

ip link

Show information for all interfaces

ip link show dev em1

Display information only for device em1

ip -s link

Display interface statistics
--------------------------------------------------------------------------------------------------------
route  
	

Display and alter the routing table

ip route

List all of the route entries in the kernel
--------------------------------------------------------------------------------------------------------
maddr
	

Manage and display multicast IP addresses

ip maddr

Display multicast information for all devices

ip maddr show dev em1

Display multicast information for device em1
--------------------------------------------------------------------------------------------------------
neigh
	

Show neighbour objects; also known as the ARP table for IPv4

ip neigh

Display neighbour objects

ip neigh show dev em1

Show the ARP cache for device em1
--------------------------------------------------------------------------------------------------------
help
	

Display a list of commands and arguments for each subcommand

ip help

Display ip commands and arguments

ip addr help

Display address commands and arguments

ip link help

Display link commands and arguments

ip neigh help

Display neighbour commands and arguments
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