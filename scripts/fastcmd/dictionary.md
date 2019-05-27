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
grep --basic-regexp "^.\{1,35\}$"
echo "Hello" | grep --extended-regexp "^.{1,35}$"
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
docker stop $(docker ps -a -q)
docker rm $(docker ps -a -q)
--------------------------------------------------------------------------------------------------------
git log --graph --pretty=format:'%Cred%h%Creset -%C(yellow)%d%Creset %s %Cgreen(%cr) %C(bold blue)<%an>%Creset' --abbrev-commit
git config --global alias.lg "log --color --graph --pretty=format:'%Cred%h%Creset -%C(yellow)%d%Creset %s %Cgreen(%cr) %C(bold blue)<%an>%Creset' --abbrev-commit"
git lg
git lg -p
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
sudo apt install kodi
sudo apt install software-properties-common
sudo add-apt-repository ppa:team-xbmc/ppa
sudo apt update
sudo apt install kodi

sudo apt update
sudo apt install kodi

sudo dnf install https://download1.rpmfusion.org/free/fedora/rpmfusion-free-release-$(rpm -E %fedora).noarch.rpm https://download1.rpmfusion.org/nonfree/fedora/rpmfusion-nonfree-release-$(rpm -E %fedora).noarch.rpm
sudo gedit /etc/selinux/config
sudo dnf install kodi

pacman -Syu
pacman -S kodi


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
mvn clean package -Pprod
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
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
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(
  classes = AppConfig.class,
  loader = AnnotationConfigContextLoader.class)
public class SpringRetryTest {
    @Autowired
    private MyService myService;

    @Autowired
    private RetryTemplate retryTemplate;

    @Test(expected = RuntimeException.class)
    public void givenTemplateRetryService_whenCallWithException_thenRetry() {
        retryTemplate.execute(arg0 -> {
            myService.templateRetryService();
            return null;
        });
    }
}
    @Autowired
    private RetryTemplate retryTemplate;

    retryTemplate.execute(arg0 -> {
            myService.templateRetryService();
            return null;
        });               

   retryTemplate.execute(new RetryCallback<Void, RuntimeException>() {
    @Override
    public Void doWithRetry(RetryContext arg0) {
        myService.templateRetryService();
    }
});
--------------------------------------------------------------------------------------------------------
1. Change Number of Content Processes

Do you like to work with a lot of tabs open at any one time, or do you rarely have more than, say, 5 tabs open? The more content processes you have, the more CPU resources will be assigned to each tab (which will also use more RAM).

If you have a powerful PC, then you can set this at a reasonably high number, which should improve the stability and performance of each open tab in Firefox. The name of this setting in about:config is dom.ipc.processCount

Default value: 4

Modified value: 7-12 (depending on number of tabs you usually have open)
2. Disable Unnecessary Animations

Animations in Firefox Quantum are not a bad thing, but if you have an old PC where every MB of RAM counts or simply don’t need these animated flourishes, you can disable them by going to toolkit.cosmeticAnimations.enabled and setting the value to “false.”

Default value: true
Modified value: false
3. Change Minimum Tab Width

It will take a more sharp-eyed Firefox user to notice this adjustment Mozilla made for Firefox Quantum. The default tab width is now just 76 pixels, whereas before it was 100. To adjust this, go to browser.tabs.tabMinWidth.

Default value: 76
Modified value: 100 if you want the same tab width as in older versions of Firefox, but really you can make this whatever you like. Just don’t go overboard!
4. Reduce Session History Cache, Save RAM

If you’re using an older machine, then even the typically speedy Firefox may slow down your PC with the default settings. This could be in part because of how it stores Web pages in its short-term memory (or RAM), which you can access using the Back and Forward buttons.

firefox-about-config-sessionhistory

The preference browser.sessionhistory.max_total_viewers affects how many pages Firefox stores in such a way that they load super fast.

Default value: – 1 (adaptable)
Modified value: any number, reflecting the number of pages you want to store. (We recommend less than 4 if your PC is struggling for speed, while those with 4GB plus can go for 8 or more.)

The preference browser.sessionhistory.max_entries affects how many pages each tab stores in its Back/Forward history altogether.

Default value: 50
Modified value:If your PC is struggling, lower this to 25, check if it helps, then adjust accordingly.
5. Disable Extension Compatibility Checks

Compatibility checks. Who needs ’em, right? Actually they’re pretty handy as a general reference of which extensions will work with your version of Firefox and which won’t, but Firefox doesn’t always get it right. If you want to see whether an extension that Firefox claims is incompatible may actually work, do the following:

    Right-click anywhere on the about:config page, then click “New -> Boolean”
    Type extensions.checkCompatibility into the box, click OK, then select “false” and click OK again.
    This preference will now exist in your list, and you can disable it at any time by right-clicking it and clicking “Reset.”

about-config-disable-compatibility-check
6. Change Firefox Download Location

By default, Firefox downloads go to the Windows “Downloads” folder, but you can change this by tweaking browser.download.folderList

Default value: 1
Modified values:

    0 – Saves all downloads to the desktop
    2 – Saves to the same location as the previous download

7. Get Asked Where You Want Each Download Saved

If you want to have more direct control over your downloads and decide what directory you want each one to be saved in, change the preference browser.download.useDownloadDir to “false.”

Default value: true
Modified value: false – prompts you where to save each download

about-config-firefox-tricks-download-locations
8. Open New Tab for Search Box Results

By default, the things you search for in the Firefox search box open in the current tab. To open in a new tab instead, you’ll need to modify browser.search.openintab

Default value: false – opens search results in current tab
Modified value: true – opens search results in new tab
9. New Tabs Page

Firefox’s New Tabs page organizes all the sites you’ve bookmarked and are most likely to visit in a convenient grid. Best of all, you can tweak how big this grid is, so while it uses 3×3 thumbnails by default, you can change it thanks to the browser.newtabpage.rows and browser.newtabpage.columns preferences.

Default value: 3 in “rows,” 5 in “columns”
Modified values: Whatever number you like!

about-config-firefox-tricks-change-columns
10. Adjust the Smart Location Bar’s Number of Suggestions

In Firefox when you start typing in the location (or URL) bar, a dropdown list of suggested sites will be shown. If you want it to show more (or less) than ten suggestions, you can adjust the browser.urlbar.maxRichResults keys and get it to show the number you want.

Default value: 10
Modified value: Set to your desired number of suggestions. If you want to disable it altogether, set it to -1.
11. Adjust the Session Restore Saving Frequency

Firefox saves your session every fifteen seconds by default, but you can change the value of browser.sessionstore.interval so that Firefox will save the session at a longer interval.

Default: 15000 (in msecs, equivalent to fifteen seconds)
Modified value: Set it to your desired value. 1000 means one sec, and 60000 means one minute
12. Extend Scripts’ Execution Time

In Firefox a script is only given ten seconds to respond, after which it will issue an unresponsive script warning. If you are stuck on a slow network connection, you might want to increase the script execution time via dom.max_script_run_time to cut down on the frequency of the no-script warning.

Default value: 10 (in secs)
Modified value: 20, or any value greater than 10
13. Handling JavaScript Popups

When you come across a site that executes a javascript, open a new window function, and if the popup window is without all the usual window features, e.g. back/forward/reload buttons, status bar, etc., Firefox will automatically treat it as a popup and will not open it as a new tab. However, if you find this to be a nuisance and want to open all new windows in new tabs, you can specify it via the browser.link.open_newwindow.restriction setting.

Default value: 2 – Open all JavaScript windows the same way you have Firefox handle new windows unless the JavaScript call specifies how to display the window

Modified values:

    0 – open all links the way you have Firefox handle new windows
    1 – do not open any new windows
    2 – open all links the way you have Firefox handle new windows unless Javascript specifies how to display the window

14. Enable Spell-Checking in All Text Fields

The default spell-checking function only checks for multi-line text boxes. You can change the option in layout.spellcheckDefault to get it to spell-check for single line text boxes as well.

Default value: 1 (spellcheck for multi-line text boxes only)
Modified values:

    0 – disable spellcheck
    2 – enable spell-check for all text boxes

about-config-firefox-tricks-spellcheck
15. Lower Memory Usage When Minimized

This tweak is mainly for Windows users. When you minimize Firefox, it will send Firefox to your virtual memory and free up your physical memory for other programs to use. Firefox will reduce its physical memory usage, when minimized, to approximately 10MB (give or take some), and when you maximize Firefox it will take back the memory that it needs.

The preference name does not exist and needs to be created.

Right-click on the background and select “New -> Boolean.”

Enter the name when prompted: config.trim_on_minimize

Enter the value: True
16. Increase/Decrease the Amount of Disk Cache

When a page is loaded, Firefox will cache it into the hard disk so that it doesn’t need to be downloaded again the next time it is loaded. The bigger the storage size you cater for Firefox, the more pages it can cache.

Before you increase the disk cache size, make sure that browser.cache.disk.enable is set to “True.”

Config name: browser.cache.disk.capacity
Default value: 50000 (in KB)
Modified value:

    0 – disable disk caching
    Any value lower than 50000 reduces the disk cache
    Any value higher than 50000 increases the disk cache

17. Select All Text When You Click on the URL Bar

In Windows and Mac Firefox highlights all text when you click on the URL bar. In Linux it does not select all the text. Instead, it places the cursor at the insertion point. Regardless of which platform you are using, you can tweak browser.urlbar.clickSelectsAll to either select all or place the cursor at the insertion point.

Modified value:

    False – place cursor at the insertion point
    True – select all text when you click

18. Same Zoom Level for Every Site

Firefox remembers your zoom preference for each site and sets it to your preferences whenever you load the page. If you want the zoom level to be consistent from site to site, you can toggle the value of browser.zoom.siteSpecific from “True” to “False.”

Default value: True
Modified value: False (enable same zoom preferences for every site)
19. Setting Your Zoom Limit

If you find that the max/min zoom level is still not sufficient for your viewing, you can change the zoom limit to suit your viewing habits.

Config name: zoom.maxPercent
Default value: 300 (percent)
Modified value: any value higher than 300

Config name: zoom.minPercent
Default value: 30 (percent)
Modified value: any value
20. Configure Your Backspace Button

In Firefox you can set your backspace by getting it to either go back to the previous page or scroll up a page if it’s a scrolling site. Holding Shift as a modifier will go forward a page if the value is set to 0 and scroll down if the value is set to 1.

Config name: browser.backspace_action
Default value: 0 – goes back a page
Modified value: 1 – scrolls up a page

about-config-firefox-tricks-backspace-config
21. Increase Offline Cache

If you do not have access to the Internet most of the time, you might want to increase the offline cache so that you can continue to work offline. By default, Firefox caches 500MB of data from supported offline web apps. You can change that value to any amount you like.

Config name: browser.cache.offline.capacity
Default value: 512000 (in KB)
Modified value: any value higher than 512000 will increase the cache value
22. Disable Delay Time When Installing Add-ons

Every time you install a Firefox add-on, you will have to wait for several seconds before the actual installation starts. To cut down on this waiting time, you can turn the preference security.dialog_enable_delay off so that the installation will begin immediately.

Default value: 1000 (in msec)
Modified value:

    0 – starts installation immediately
    any other value (in msec)

about-config-firefox-tricks-security-dialog-delay
23. View Source in Your Favorite Editor

This is very useful for developers who are always using the “view source” function. This tweak allows you to view the source code of a given website in an external editor.

There are two configurations that need to be made:

Config name: view_source.editor.external
Default value: False
Modified value: True (enable view source using external text editor)

Config name: view_source.editor.path
Default value: blank
Modified value: insert the file path to your editor here
24. Increasing “Save Link As” Timeout Value

When you right-click and select “Save Link As … ” the browser will request the content disposition header from the URL to determine the filename. If the URL does not deliver the header within one second, Firefox will issue a timeout value. This could happen very frequently in a slow network connection environment. To prevent this issue from happening frequently, you can increase the timeout value to reduce the possibility of a timeout by editing Browser.download.saveLinkAsFilenameTimeout

Default value: 4000 (4 seconds)
Modified value: any value higher than 1000 (value is in msec)
25. Autohide Toolbar in Fullscreen Mode

In fullscreen mode the toolbar is set to autohide and appear only when you hover over it with your mouse. If you want, you can choose to have it visible all the time instead by toggling the value of browser.fullscreen.autohide to “False” to always show the toolbar.

Default value: True (always autohide)
Modified value: False (always show the toolbar)
26. Increase Add-on Search Result

If you go to “Tools -> Add-ons -> Get Add-ons” and perform a search, Firefox will display fifteen matching results. If you want more or less results here, you can adjust extensions.getAddons.maxResults
--------------------------------------------------------------------------------------------------------
spring.jpa.properties.hibernate.jdbc.lob.non_contextual_creation=true
 
/*
 * The MIT License
 *
 * Copyright 2017 WildBees Labs.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package com.wildbeeslabs.api.rest.subscription.configuration;

import com.mchange.v2.c3p0.ComboPooledDataSource;
import com.wildbeeslabs.api.rest.common.service.interfaces.IPropertiesConfiguration;

import java.util.Properties;
import javax.naming.NamingException;
import javax.persistence.EntityManagerFactory;
import javax.sql.DataSource;
import java.beans.PropertyVetoException;

import org.hibernate.SessionFactory;
import com.zaxxer.hikari.HikariDataSource;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.jdbc.DataSourceBuilder;
import org.springframework.boot.autoconfigure.jdbc.DataSourceProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.JpaVendorAdapter;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.dao.annotation.PersistenceExceptionTranslationPostProcessor;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.orm.hibernate5.LocalSessionFactoryBean;
import org.springframework.orm.jpa.persistenceunit.DefaultPersistenceUnitManager;
import org.springframework.orm.jpa.persistenceunit.PersistenceUnitManager;
import org.springframework.orm.jpa.support.PersistenceAnnotationBeanPostProcessor;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

/**
 *
 * Application JPA Configuration
 *
 * @author Alex
 * @version 1.0.0
 * @since 2017-08-08
 */
@Configuration("subscriptionJpaConfiguration")
@EnableAutoConfiguration
@EnableAsync
@EnableJpaAuditing
@EnableTransactionManagement
@EnableJpaRepositories(basePackages = {"com.wildbeeslabs.api.rest.subscription.repository"},
        entityManagerFactoryRef = "entityManagerFactory",
        transactionManagerRef = "transactionManager")
//@ImportResource("classpath:hibernate.cfg.xml")
//@PropertySource({"classpath:application.default.yml"})
public class JpaConfiguration {

//    @PersistenceContext(unitName = "ds2", type = PersistenceContextType.TRANSACTION)
//    private EntityManager em;
    @Autowired
    @Qualifier("subscriptionPropertiesConfiguration")
    private IPropertiesConfiguration propertyConfig;

    /**
     * Get Property Source placeholder
     *
     * @return property source placeholder
     */
    @Bean
    public static PropertySourcesPlaceholderConfigurer propertySourcesPlaceholderConfigurer() {
        return new PropertySourcesPlaceholderConfigurer();
    }

    /**
     * Get Default DataSource properties
     *
     * @return default DataSource properties
     */
    @Bean
    @Primary
    @ConfigurationProperties(ignoreInvalidFields = true, prefix = "datasource.subscriptionapp")
    public DataSourceProperties dataSourceProperties() {
        return new DataSourceProperties();
    }

    /**
     * Get DataSource configuration
     *
     * @return DataSource configuration
     */
    @Bean
    public DataSource dataSource() {
        final DataSourceProperties dataSourceProperties = dataSourceProperties();
        HikariDataSource dataSource = (HikariDataSource) DataSourceBuilder
                .create(dataSourceProperties.getClassLoader())
                .driverClassName(dataSourceProperties.getDriverClassName())
                .url(dataSourceProperties.getUrl())
                .username(dataSourceProperties.getUsername())
                .password(dataSourceProperties.getPassword())
                .type(HikariDataSource.class)
                .build();
        // Basic datasource properties
        //dataSource.setAllowPoolSuspension(propertyConfig.getProperty("datasource.subscriptionapp.allowPoolSuspension", Boolean.class));
        //dataSource.setAutoCommit(propertyConfig.getProperty("datasource.subscriptionapp.autoCommit", Boolean.class));
        //dataSource.setMaximumPoolSize(propertyConfig.getProperty("datasource.subscriptionapp.maxPoolSize", Integer.class));
        // MySQL specific properties
        /*dataSource.addDataSourceProperty("cachePrepStmts", propertyConfig.getProperty("datasource.subscriptionapp.cachePrepStmts"));
        dataSource.addDataSourceProperty("prepStmtCacheSize", propertyConfig.getProperty("datasource.subscriptionapp.prepStmtCacheSize"));
        dataSource.addDataSourceProperty("prepStmtCacheSqlLimit", propertyConfig.getProperty("datasource.subscriptionapp.prepStmtCacheSqlLimit"));
        dataSource.addDataSourceProperty("useServerPrepStmts", propertyConfig.getProperty("datasource.subscriptionapp.useServerPrepStmts"));
        dataSource.addDataSourceProperty("useLocalSessionState", propertyConfig.getProperty("datasource.subscriptionapp.useLocalSessionState"));
        dataSource.addDataSourceProperty("useLocalTransactionState", propertyConfig.getProperty("datasource.subscriptionapp.useLocalTransactionState"));
        dataSource.addDataSourceProperty("rewriteBatchedStatements", propertyConfig.getProperty("datasource.subscriptionapp.rewriteBatchedStatements"));
        dataSource.addDataSourceProperty("cacheResultSetMetadata", propertyConfig.getProperty("datasource.subscriptionapp.cacheResultSetMetadata"));
        dataSource.addDataSourceProperty("cacheServerConfiguration", propertyConfig.getProperty("datasource.subscriptionapp.cacheServerConfiguration"));
        dataSource.addDataSourceProperty("elideSetAutoCommits", propertyConfig.getProperty("datasource.subscriptionapp.elideSetAutoCommits"));
        dataSource.addDataSourceProperty("maintainTimeStats", propertyConfig.getProperty("datasource.subscriptionapp.maintainTimeStats"));
        dataSource.addDataSourceProperty("allowUrlInLocalInfile", propertyConfig.getProperty("datasource.subscriptionapp.allowUrlInLocalInfile"));
        dataSource.addDataSourceProperty("useReadAheadInput", propertyConfig.getProperty("datasource.subscriptionapp.useReadAheadInput"));
        dataSource.addDataSourceProperty("useUnbufferedIO", propertyConfig.getProperty("datasource.subscriptionapp.useUnbufferedIO"));*/
        return dataSource;
    }

    /**
     * Get Combo pool DataSource configuration
     *
     * @return DataSource configuration
     * @throws java.beans.PropertyVetoException
     */
    //@Bean
    public DataSource dataSource2() throws PropertyVetoException {
        final ComboPooledDataSource dataSource2 = new ComboPooledDataSource();
        dataSource2.setAcquireIncrement(propertyConfig.getProperty("datasource.subscriptionapp.acquireIncrement", Integer.class));
        dataSource2.setMaxStatementsPerConnection(propertyConfig.getProperty("datasource.subscriptionapp.maxStatementsPerConnection", Integer.class));
        dataSource2.setMaxStatements(propertyConfig.getProperty("datasource.subscriptionapp.maxStatements", Integer.class));
        dataSource2.setMaxPoolSize(propertyConfig.getProperty("datasource.subscriptionapp.maxPoolSize", Integer.class));
        dataSource2.setMinPoolSize(propertyConfig.getProperty("datasource.subscriptionapp.minPoolSize", Integer.class));
        dataSource2.setJdbcUrl(propertyConfig.getMandatoryProperty("datasource.subscriptionapp.url"));
        dataSource2.setUser(propertyConfig.getMandatoryProperty("datasource.subscriptionapp.username"));
        dataSource2.setPassword(propertyConfig.getMandatoryProperty("datasource.subscriptionapp.password"));
        dataSource2.setDriverClass(propertyConfig.getMandatoryProperty("datasource.subscriptionapp.driverClassName"));
        return dataSource2;
    }

    /**
     * Get DataSource configuration
     *
     * @return DataSource configuration
     * @throws java.beans.PropertyVetoException
     */
    //@Bean
    public DataSource dataSource3() throws PropertyVetoException {
        final DriverManagerDataSource dataSource = new DriverManagerDataSource();
        dataSource.setDriverClassName(propertyConfig.getMandatoryProperty("datasource.subscriptionapp.driverClassName"));
        dataSource.setUrl(propertyConfig.getMandatoryProperty("datasource.subscriptionapp.url"));
        dataSource.setUsername(propertyConfig.getMandatoryProperty("datasource.subscriptionapp.username"));
        dataSource.setPassword(propertyConfig.getMandatoryProperty("datasource.subscriptionapp.password"));
        return dataSource;
    }

    /**
     * Get Entity Manager Factory bean
     *
     * @return local container emf bean
     * @throws javax.naming.NamingException
     */
    @Bean
    public LocalContainerEntityManagerFactoryBean entityManagerFactory() throws NamingException {
        LocalContainerEntityManagerFactoryBean factoryBean = new LocalContainerEntityManagerFactoryBean();
        factoryBean.setDataSource(dataSource());
        factoryBean.setPackagesToScan(new String[]{"com.wildbeeslabs.api.rest.common.model", "com.wildbeeslabs.api.rest.subscription.model"});
        factoryBean.setJpaVendorAdapter(jpaVendorAdapter());
        factoryBean.setJpaProperties(jpaProperties());
        factoryBean.setPersistenceUnitName("local");
//        factoryBean.setPersistenceUnitManager(persistenceUnitManager());
        return factoryBean;
    }

    /**
     * Get Hibernate JPA adapter
     *
     * @return hibernate JPA adapter
     */
    @Bean
    public JpaVendorAdapter jpaVendorAdapter() {
        HibernateJpaVendorAdapter hibernateJpaVendorAdapter = new HibernateJpaVendorAdapter();
//        hibernateJpaVendorAdapter.setShowSql(true);
//        hibernateJpaVendorAdapter.setGenerateDdl(true);
//        hibernateJpaVendorAdapter.setDatabasePlatform(propertyConfig.getMandatoryProperty("datasource.subscriptionapp.hibernate.dialect"));
        return hibernateJpaVendorAdapter;
    }

    /**
     * Get Persistence exception translation processor
     *
     * @return persistence exception translation processor
     */
    @Bean
    public PersistenceExceptionTranslationPostProcessor exceptionTranslation() {
        return new PersistenceExceptionTranslationPostProcessor();
    }

    /**
     * Get JPA properties configuration
     *
     * @return JPA properties configuration
     */
    private Properties jpaProperties() {
        final Properties properties = new Properties();
        properties.put("hibernate.dialect", propertyConfig.getMandatoryProperty("datasource.subscriptionapp.hibernate.dialect"));
        properties.put("hibernate.hbm2ddl.auto", propertyConfig.getProperty("datasource.subscriptionapp.hibernate.hbm2ddl.method"));
        properties.put("hibernate.show_sql", propertyConfig.getProperty("datasource.subscriptionapp.hibernate.showSql"));
        properties.put("hibernate.format_sql", propertyConfig.getProperty("datasource.subscriptionapp.hibernate.formatSql"));
        properties.put("hibernate.max_fetch_depth", propertyConfig.getProperty("datasource.subscriptionapp.hibernate.maxFetchDepth"));
        properties.put("hibernate.default_batch_fetch_size", propertyConfig.getProperty("datasource.subscriptionapp.hibernate.defaultBatchFetchSize"));
        properties.put("hibernate.default_schema", propertyConfig.getProperty("datasource.subscriptionapp.hibernate.defaultSchema"));
        properties.put("hibernate.globally_quoted_identifiers", propertyConfig.getProperty("datasource.subscriptionapp.hibernate.globallyQuotedIdentifiers"));
        properties.put("hibernate.generate_statistics", propertyConfig.getProperty("datasource.subscriptionapp.hibernate.generateStatistics"));
        properties.put("hibernate.bytecode.use_reflection_optimizer", propertyConfig.getProperty("datasource.subscriptionapp.hibernate.bytecode.useReflectionOptimizer"));

        // Configure Lucene Search
        properties.put("spring.jpa.properties.hibernate.search.default.directory_provider", propertyConfig.getProperty("spring.jpa.properties.hibernate.search.default.directoryProvider"));
        properties.put("spring.jpa.properties.hibernate.search.default.indexBase", propertyConfig.getProperty("spring.jpa.properties.hibernate.search.default.indexBase"));
        properties.put("spring.jpa.properties.hibernate.search.default.batch.merge_factor", propertyConfig.getProperty("spring.jpa.properties.hibernate.search.default.batch.mergeFactor"));
        properties.put("spring.jpa.properties.hibernate.search.default.batch.max_buffered_docs", propertyConfig.getProperty("spring.jpa.properties.hibernate.search.default.batch.maxBufferedDocs"));

        if (StringUtils.isNotEmpty(propertyConfig.getProperty("datasource.subscriptionapp.hibernate.hbm2ddl.importFiles"))) {
            properties.put("hibernate.hbm2ddl.import_files", propertyConfig.getProperty("datasource.subscriptionapp.hibernate.hbm2ddl.importFiles"));
        }

        // Configure Hibernate Cache
        properties.put("hibernate.cache.use_second_level_cache", propertyConfig.getProperty("datasource.subscriptionapp.hibernate.cache.useSecondLevelCache"));
        properties.put("hibernate.cache.use_query_cache", propertyConfig.getProperty("datasource.subscriptionapp.hibernate.cache.useQueryCache"));
        properties.put("hibernate.cache.region.factory_class", propertyConfig.getProperty("datasource.subscriptionapp.hibernate.cache.region.factoryClass"));

        // Configure Connection Pool
        properties.put("hibernate.c3p0.min_size", propertyConfig.getProperty("datasource.subscriptionapp.hibernate.c3p0.minSize"));
        properties.put("hibernate.c3p0.max_size", propertyConfig.getProperty("datasource.subscriptionapp.hibernate.c3p0.maxSize"));
        properties.put("hibernate.c3p0.timeout", propertyConfig.getProperty("datasource.subscriptionapp.hibernate.c3p0.timeout"));
        properties.put("hibernate.c3p0.max_statements", propertyConfig.getProperty("datasource.subscriptionapp.hibernate.c3p0.maxStatements"));
        properties.put("hibernate.c3p0.idle_test_period", propertyConfig.getProperty("datasource.subscriptionapp.hibernate.c3p0.idleTestPeriod"));
        return properties;
    }

    /**
     * Get Transaction Manager
     *
     * @param emf - entity manager factory
     * @return transaction manager
     */
    @Bean
    @Autowired
    public PlatformTransactionManager transactionManager(final EntityManagerFactory emf) {
        JpaTransactionManager txManager = new JpaTransactionManager();
        txManager.setEntityManagerFactory(emf);
        return txManager;
    }

    /**
     * Get Session Factory bean
     *
     * @return session factory bean
     */
    @Bean
    public FactoryBean<SessionFactory> sessionFactory() {
        LocalSessionFactoryBean sessionFactory = new LocalSessionFactoryBean();
        sessionFactory.setDataSource(dataSource());
        return sessionFactory;
    }

    /**
     * Get Persistence Unit Manager
     *
     * @return persistence unit manager
     */
    @Bean
    public PersistenceUnitManager persistenceUnitManager() {
        DefaultPersistenceUnitManager manager = new DefaultPersistenceUnitManager();
        manager.setDefaultDataSource(dataSource());
        return manager;
    }

    /**
     * Get Persistence Annotation processor
     *
     * @return persistence annotation processor
     */
    @Bean
    public BeanPostProcessor postProcessor() {
        PersistenceAnnotationBeanPostProcessor postProcessor = new PersistenceAnnotationBeanPostProcessor();
        return postProcessor;
    }
}

 
package com.baeldung.jhipster.gateway.gateway.responserewriting;

import com.netflix.zuul.context.RequestContext;
import org.apache.commons.io.IOUtils;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.zip.GZIPInputStream;

import static com.baeldung.jhipster.gateway.gateway.responserewriting.SwaggerBasePathRewritingFilter.gzipData;
import static org.junit.Assert.*;
import static springfox.documentation.swagger2.web.Swagger2Controller.DEFAULT_URL;

/**
 * Tests SwaggerBasePathRewritingFilter class.
 */
public class SwaggerBasePathRewritingFilterTest {

    private SwaggerBasePathRewritingFilter filter = new SwaggerBasePathRewritingFilter();

    @Test
    public void shouldFilter_on_default_swagger_url() {

        MockHttpServletRequest request = new MockHttpServletRequest("GET", DEFAULT_URL);
        RequestContext.getCurrentContext().setRequest(request);

        assertTrue(filter.shouldFilter());
    }

    /**
     * Zuul DebugFilter can be triggered by "deug" parameter.
     */
    @Test
    public void shouldFilter_on_default_swagger_url_with_param() {

        MockHttpServletRequest request = new MockHttpServletRequest("GET", DEFAULT_URL);
        request.setParameter("debug", "true");
        RequestContext.getCurrentContext().setRequest(request);

        assertTrue(filter.shouldFilter());
    }

    @Test
    public void shouldNotFilter_on_wrong_url() {

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/management/info");
        RequestContext.getCurrentContext().setRequest(request);

        assertFalse(filter.shouldFilter());
    }

    @Test
    public void run_on_valid_response() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/service1" + DEFAULT_URL);
        RequestContext context = RequestContext.getCurrentContext();
        context.setRequest(request);

        MockHttpServletResponse response = new MockHttpServletResponse();
        context.setResponseGZipped(false);
        context.setResponse(response);

        InputStream in = IOUtils.toInputStream("{\"basePath\":\"/\"}", StandardCharsets.UTF_8);
        context.setResponseDataStream(in);

        filter.run();

        assertEquals("UTF-8", response.getCharacterEncoding());
        assertEquals("{\"basePath\":\"/service1\"}", context.getResponseBody());
    }

    @Test
    public void run_on_valid_response_gzip() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/service1" + DEFAULT_URL);
        RequestContext context = RequestContext.getCurrentContext();
        context.setRequest(request);

        MockHttpServletResponse response = new MockHttpServletResponse();
        context.setResponseGZipped(true);
        context.setResponse(response);

        context.setResponseDataStream(new ByteArrayInputStream(gzipData("{\"basePath\":\"/\"}")));

        filter.run();

        assertEquals("UTF-8", response.getCharacterEncoding());

        InputStream responseDataStream = new GZIPInputStream(context.getResponseDataStream());
        String responseBody = IOUtils.toString(responseDataStream, StandardCharsets.UTF_8);
        assertEquals("{\"basePath\":\"/service1\"}", responseBody);
    }
}

 
 
package com.baeldung.jhipster.gateway.config;

import org.springframework.cloud.client.loadbalancer.RestTemplateCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.web.client.RestTemplate;

/**
 * Overrides UAA specific beans, so they do not interfere the testing
 * This configuration must be included in @SpringBootTest in order to take effect.
 */
@Configuration
public class SecurityBeanOverrideConfiguration {

    @Bean
    @Primary
    public TokenStore tokenStore() {
        return null;
    }

    @Bean
    @Primary
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        return null;
    }

    @Bean
    @Primary
    public RestTemplate loadBalancedRestTemplate(RestTemplateCustomizer customizer) {
        return null;
    }
}

 
 
 
package com.baeldung.jhipster.gateway.config;

import com.codahale.metrics.MetricRegistry;
import com.codahale.metrics.servlet.InstrumentedFilter;
import com.codahale.metrics.servlets.MetricsServlet;
import io.github.jhipster.config.JHipsterConstants;
import io.github.jhipster.config.JHipsterProperties;
import io.github.jhipster.web.filter.CachingHttpHeadersFilter;
import io.undertow.Undertow;
import io.undertow.Undertow.Builder;
import io.undertow.UndertowOptions;
import org.apache.commons.io.FilenameUtils;

import org.h2.server.web.WebServlet;
import org.junit.Before;
import org.junit.Test;
import org.springframework.boot.web.embedded.undertow.UndertowServletWebServerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockServletContext;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.xnio.OptionMap;

import javax.servlet.*;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Unit tests for the WebConfigurer class.
 *
 * @see WebConfigurer
 */
public class WebConfigurerTest {

    private WebConfigurer webConfigurer;

    private MockServletContext servletContext;

    private MockEnvironment env;

    private JHipsterProperties props;

    private MetricRegistry metricRegistry;

    @Before
    public void setup() {
        servletContext = spy(new MockServletContext());
        doReturn(mock(FilterRegistration.Dynamic.class))
            .when(servletContext).addFilter(anyString(), any(Filter.class));
        doReturn(mock(ServletRegistration.Dynamic.class))
            .when(servletContext).addServlet(anyString(), any(Servlet.class));

        env = new MockEnvironment();
        props = new JHipsterProperties();

        webConfigurer = new WebConfigurer(env, props);
        metricRegistry = new MetricRegistry();
        webConfigurer.setMetricRegistry(metricRegistry);
    }

    @Test
    public void testStartUpProdServletContext() throws ServletException {
        env.setActiveProfiles(JHipsterConstants.SPRING_PROFILE_PRODUCTION);
        webConfigurer.onStartup(servletContext);

        assertThat(servletContext.getAttribute(InstrumentedFilter.REGISTRY_ATTRIBUTE)).isEqualTo(metricRegistry);
        assertThat(servletContext.getAttribute(MetricsServlet.METRICS_REGISTRY)).isEqualTo(metricRegistry);
        verify(servletContext).addFilter(eq("webappMetricsFilter"), any(InstrumentedFilter.class));
        verify(servletContext).addServlet(eq("metricsServlet"), any(MetricsServlet.class));
        verify(servletContext).addFilter(eq("cachingHttpHeadersFilter"), any(CachingHttpHeadersFilter.class));
        verify(servletContext, never()).addServlet(eq("H2Console"), any(WebServlet.class));
    }

    @Test
    public void testStartUpDevServletContext() throws ServletException {
        env.setActiveProfiles(JHipsterConstants.SPRING_PROFILE_DEVELOPMENT);
        webConfigurer.onStartup(servletContext);

        assertThat(servletContext.getAttribute(InstrumentedFilter.REGISTRY_ATTRIBUTE)).isEqualTo(metricRegistry);
        assertThat(servletContext.getAttribute(MetricsServlet.METRICS_REGISTRY)).isEqualTo(metricRegistry);
        verify(servletContext).addFilter(eq("webappMetricsFilter"), any(InstrumentedFilter.class));
        verify(servletContext).addServlet(eq("metricsServlet"), any(MetricsServlet.class));
        verify(servletContext, never()).addFilter(eq("cachingHttpHeadersFilter"), any(CachingHttpHeadersFilter.class));
        verify(servletContext).addServlet(eq("H2Console"), any(WebServlet.class));
    }

    @Test
    public void testCustomizeServletContainer() {
        env.setActiveProfiles(JHipsterConstants.SPRING_PROFILE_PRODUCTION);
        UndertowServletWebServerFactory container = new UndertowServletWebServerFactory();
        webConfigurer.customize(container);
        assertThat(container.getMimeMappings().get("abs")).isEqualTo("audio/x-mpeg");
        assertThat(container.getMimeMappings().get("html")).isEqualTo("text/html;charset=utf-8");
        assertThat(container.getMimeMappings().get("json")).isEqualTo("text/html;charset=utf-8");
        if (container.getDocumentRoot() != null) {
            assertThat(container.getDocumentRoot().getPath()).isEqualTo(FilenameUtils.separatorsToSystem("target/www"));
        }

        Builder builder = Undertow.builder();
        container.getBuilderCustomizers().forEach(c -> c.customize(builder));
        OptionMap.Builder serverOptions = (OptionMap.Builder) ReflectionTestUtils.getField(builder, "serverOptions");
        assertThat(serverOptions.getMap().get(UndertowOptions.ENABLE_HTTP2)).isNull();
    }

    @Test
    public void testUndertowHttp2Enabled() {
        props.getHttp().setVersion(JHipsterProperties.Http.Version.V_2_0);
        UndertowServletWebServerFactory container = new UndertowServletWebServerFactory();
        webConfigurer.customize(container);
        Builder builder = Undertow.builder();
        container.getBuilderCustomizers().forEach(c -> c.customize(builder));
        OptionMap.Builder serverOptions = (OptionMap.Builder) ReflectionTestUtils.getField(builder, "serverOptions");
        assertThat(serverOptions.getMap().get(UndertowOptions.ENABLE_HTTP2)).isTrue();
    }

    @Test
    public void testCorsFilterOnApiPath() throws Exception {
        props.getCors().setAllowedOrigins(Collections.singletonList("*"));
        props.getCors().setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE"));
        props.getCors().setAllowedHeaders(Collections.singletonList("*"));
        props.getCors().setMaxAge(1800L);
        props.getCors().setAllowCredentials(true);

        MockMvc mockMvc = MockMvcBuilders.standaloneSetup(new WebConfigurerTestController())
            .addFilters(webConfigurer.corsFilter())
            .build();

        mockMvc.perform(
            options("/api/test-cors")
                .header(HttpHeaders.ORIGIN, "other.domain.com")
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "POST"))
            .andExpect(status().isOk())
            .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "other.domain.com"))
            .andExpect(header().string(HttpHeaders.VARY, "Origin"))
            .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS, "GET,POST,PUT,DELETE"))
            .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS, "true"))
            .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_MAX_AGE, "1800"));

        mockMvc.perform(
            get("/api/test-cors")
                .header(HttpHeaders.ORIGIN, "other.domain.com"))
            .andExpect(status().isOk())
            .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "other.domain.com"));
    }

    @Test
    public void testCorsFilterOnOtherPath() throws Exception {
        props.getCors().setAllowedOrigins(Collections.singletonList("*"));
        props.getCors().setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE"));
        props.getCors().setAllowedHeaders(Collections.singletonList("*"));
        props.getCors().setMaxAge(1800L);
        props.getCors().setAllowCredentials(true);

        MockMvc mockMvc = MockMvcBuilders.standaloneSetup(new WebConfigurerTestController())
            .addFilters(webConfigurer.corsFilter())
            .build();

        mockMvc.perform(
            get("/test/test-cors")
                .header(HttpHeaders.ORIGIN, "other.domain.com"))
            .andExpect(status().isOk())
            .andExpect(header().doesNotExist(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN));
    }

    @Test
    public void testCorsFilterDeactivated() throws Exception {
        props.getCors().setAllowedOrigins(null);

        MockMvc mockMvc = MockMvcBuilders.standaloneSetup(new WebConfigurerTestController())
            .addFilters(webConfigurer.corsFilter())
            .build();

        mockMvc.perform(
            get("/api/test-cors")
                .header(HttpHeaders.ORIGIN, "other.domain.com"))
            .andExpect(status().isOk())
            .andExpect(header().doesNotExist(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN));
    }

    @Test
    public void testCorsFilterDeactivated2() throws Exception {
        props.getCors().setAllowedOrigins(new ArrayList<>());

        MockMvc mockMvc = MockMvcBuilders.standaloneSetup(new WebConfigurerTestController())
            .addFilters(webConfigurer.corsFilter())
            .build();

        mockMvc.perform(
            get("/api/test-cors")
                .header(HttpHeaders.ORIGIN, "other.domain.com"))
            .andExpect(status().isOk())
            .andExpect(header().doesNotExist(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN));
    }
}

 
 
 
 
package com.baeldung.jhipster.gateway.security;

import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.stereotype.Component;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.mockito.BDDMockito.given;

/**
 * A bean providing simple mocking of OAuth2 access tokens for security integration tests.
 */
@Component
public class OAuth2TokenMockUtil {

    @MockBean
    private ResourceServerTokenServices tokenServices;

    private OAuth2Authentication createAuthentication(String username, Set<String> scopes, Set<String> roles) {
        List<GrantedAuthority> authorities = roles.stream()
            .map(SimpleGrantedAuthority::new)
            .collect(Collectors.toList());

        User principal = new User(username, "test", true, true, true, true, authorities);
        Authentication authentication = new UsernamePasswordAuthenticationToken(principal, principal.getPassword(),
            principal.getAuthorities());

        // Create the authorization request and OAuth2Authentication object
        OAuth2Request authRequest = new OAuth2Request(null, "testClient", null, true, scopes, null, null, null,
            null);
        return new OAuth2Authentication(authRequest, authentication);
    }

    public RequestPostProcessor oauth2Authentication(String username, Set<String> scopes, Set<String> roles) {
        String uuid = String.valueOf(UUID.randomUUID());

        given(tokenServices.loadAuthentication(uuid))
            .willReturn(createAuthentication(username, scopes, roles));

        given(tokenServices.readAccessToken(uuid)).willReturn(new DefaultOAuth2AccessToken(uuid));

        return new OAuth2PostProcessor(uuid);
    }

    public RequestPostProcessor oauth2Authentication(String username, Set<String> scopes) {
        return oauth2Authentication(username, scopes, Collections.emptySet());
    }

    public RequestPostProcessor oauth2Authentication(String username) {
        return oauth2Authentication(username, Collections.emptySet());
    }

    public static class OAuth2PostProcessor implements RequestPostProcessor {

        private String token;

        public OAuth2PostProcessor(String token) {
            this.token = token;
        }

        @Override
        public MockHttpServletRequest postProcessRequest(MockHttpServletRequest mockHttpServletRequest) {
            mockHttpServletRequest.addHeader("Authorization", "Bearer " + token);

            return mockHttpServletRequest;
        }
    }
}

 
 
 
 
package com.baeldung.jhipster.gateway.web.rest.errors;

import org.springframework.dao.ConcurrencyFailureException;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import java.util.HashMap;
import java.util.Map;

@RestController
public class ExceptionTranslatorTestController {

    @GetMapping("/test/concurrency-failure")
    public void concurrencyFailure() {
        throw new ConcurrencyFailureException("test concurrency failure");
    }

    @PostMapping("/test/method-argument")
    public void methodArgument(@Valid @RequestBody TestDTO testDTO) {
    }

    @GetMapping("/test/parameterized-error")
    public void parameterizedError() {
        throw new CustomParameterizedException("test parameterized error", "param0_value", "param1_value");
    }

    @GetMapping("/test/parameterized-error2")
    public void parameterizedError2() {
        Map<String, Object> params = new HashMap<>();
        params.put("foo", "foo_value");
        params.put("bar", "bar_value");
        throw new CustomParameterizedException("test parameterized error", params);
    }

    @GetMapping("/test/missing-servlet-request-part")
    public void missingServletRequestPartException(@RequestPart String part) {
    }

    @GetMapping("/test/missing-servlet-request-parameter")
    public void missingServletRequestParameterException(@RequestParam String param) {
    }

    @GetMapping("/test/access-denied")
    public void accessdenied() {
        throw new AccessDeniedException("test access denied!");
    }

    @GetMapping("/test/unauthorized")
    public void unauthorized() {
        throw new BadCredentialsException("test authentication failed!");
    }

    @GetMapping("/test/response-status")
    public void exceptionWithReponseStatus() {
        throw new TestResponseStatusException();
    }

    @GetMapping("/test/internal-server-error")
    public void internalServerError() {
        throw new RuntimeException();
    }

    public static class TestDTO {

        @NotNull
        private String test;

        public String getTest() {
            return test;
        }

        public void setTest(String test) {
            this.test = test;
        }
    }

    @ResponseStatus(value = HttpStatus.BAD_REQUEST, reason = "test response status")
    @SuppressWarnings("serial")
    public static class TestResponseStatusException extends RuntimeException {
    }

}

 
 
 
package com.baeldung.jhipster.gateway.web.rest.errors;

import com.baeldung.jhipster.gateway.GatewayApp;
import com.baeldung.jhipster.gateway.config.SecurityBeanOverrideConfiguration;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Test class for the ExceptionTranslator controller advice.
 *
 * @see ExceptionTranslator
 */
@RunWith(SpringRunner.class)
@SpringBootTest(classes = {SecurityBeanOverrideConfiguration.class, GatewayApp.class})
public class ExceptionTranslatorIntTest {

    @Autowired
    private ExceptionTranslatorTestController controller;

    @Autowired
    private ExceptionTranslator exceptionTranslator;

    @Autowired
    private MappingJackson2HttpMessageConverter jacksonMessageConverter;

    private MockMvc mockMvc;

    @Before
    public void setup() {
        mockMvc = MockMvcBuilders.standaloneSetup(controller)
            .setControllerAdvice(exceptionTranslator)
            .setMessageConverters(jacksonMessageConverter)
            .build();
    }

    @Test
    public void testConcurrencyFailure() throws Exception {
        mockMvc.perform(get("/test/concurrency-failure"))
            .andExpect(status().isConflict())
            .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON))
            .andExpect(jsonPath("$.message").value(ErrorConstants.ERR_CONCURRENCY_FAILURE));
    }

    @Test
    public void testMethodArgumentNotValid() throws Exception {
         mockMvc.perform(post("/test/method-argument").content("{}").contentType(MediaType.APPLICATION_JSON))
             .andExpect(status().isBadRequest())
             .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON))
             .andExpect(jsonPath("$.message").value(ErrorConstants.ERR_VALIDATION))
             .andExpect(jsonPath("$.fieldErrors.[0].objectName").value("testDTO"))
             .andExpect(jsonPath("$.fieldErrors.[0].field").value("test"))
             .andExpect(jsonPath("$.fieldErrors.[0].message").value("NotNull"));
    }

    @Test
    public void testParameterizedError() throws Exception {
        mockMvc.perform(get("/test/parameterized-error"))
            .andExpect(status().isBadRequest())
            .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON))
            .andExpect(jsonPath("$.message").value("test parameterized error"))
            .andExpect(jsonPath("$.params.param0").value("param0_value"))
            .andExpect(jsonPath("$.params.param1").value("param1_value"));
    }

    @Test
    public void testParameterizedError2() throws Exception {
        mockMvc.perform(get("/test/parameterized-error2"))
            .andExpect(status().isBadRequest())
            .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON))
            .andExpect(jsonPath("$.message").value("test parameterized error"))
            .andExpect(jsonPath("$.params.foo").value("foo_value"))
            .andExpect(jsonPath("$.params.bar").value("bar_value"));
    }

    @Test
    public void testMissingServletRequestPartException() throws Exception {
        mockMvc.perform(get("/test/missing-servlet-request-part"))
            .andExpect(status().isBadRequest())
            .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON))
            .andExpect(jsonPath("$.message").value("error.http.400"));
    }

    @Test
    public void testMissingServletRequestParameterException() throws Exception {
        mockMvc.perform(get("/test/missing-servlet-request-parameter"))
            .andExpect(status().isBadRequest())
            .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON))
            .andExpect(jsonPath("$.message").value("error.http.400"));
    }

    @Test
    public void testAccessDenied() throws Exception {
        mockMvc.perform(get("/test/access-denied"))
            .andExpect(status().isForbidden())
            .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON))
            .andExpect(jsonPath("$.message").value("error.http.403"))
            .andExpect(jsonPath("$.detail").value("test access denied!"));
    }

    @Test
    public void testUnauthorized() throws Exception {
        mockMvc.perform(get("/test/unauthorized"))
            .andExpect(status().isUnauthorized())
            .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON))
            .andExpect(jsonPath("$.message").value("error.http.401"))
            .andExpect(jsonPath("$.path").value("/test/unauthorized"))
            .andExpect(jsonPath("$.detail").value("test authentication failed!"));
    }

    @Test
    public void testMethodNotSupported() throws Exception {
        mockMvc.perform(post("/test/access-denied"))
            .andExpect(status().isMethodNotAllowed())
            .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON))
            .andExpect(jsonPath("$.message").value("error.http.405"))
            .andExpect(jsonPath("$.detail").value("Request method 'POST' not supported"));
    }

    @Test
    public void testExceptionWithResponseStatus() throws Exception {
        mockMvc.perform(get("/test/response-status"))
            .andExpect(status().isBadRequest())
            .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON))
            .andExpect(jsonPath("$.message").value("error.http.400"))
            .andExpect(jsonPath("$.title").value("test response status"));
    }

    @Test
    public void testInternalServerError() throws Exception {
        mockMvc.perform(get("/test/internal-server-error"))
            .andExpect(status().isInternalServerError())
            .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON))
            .andExpect(jsonPath("$.message").value("error.http.500"))
            .andExpect(jsonPath("$.title").value("Internal Server Error"));
    }

}

 
 
 
package com.baeldung.jhipster.gateway.web.rest;

import com.baeldung.jhipster.gateway.GatewayApp;
import com.baeldung.jhipster.gateway.config.SecurityBeanOverrideConfiguration;
import com.baeldung.jhipster.gateway.web.rest.vm.LoggerVM;
import ch.qos.logback.classic.AsyncAppender;
import ch.qos.logback.classic.LoggerContext;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.LoggerFactory;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Test class for the LogsResource REST controller.
 *
 * @see LogsResource
 */
@RunWith(SpringRunner.class)
@SpringBootTest(classes = {SecurityBeanOverrideConfiguration.class, GatewayApp.class})
public class LogsResourceIntTest {

    private MockMvc restLogsMockMvc;

    @Before
    public void setup() {
        LogsResource logsResource = new LogsResource();
        this.restLogsMockMvc = MockMvcBuilders
            .standaloneSetup(logsResource)
            .build();
    }

    @Test
    public void getAllLogs() throws Exception {
        restLogsMockMvc.perform(get("/management/logs"))
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8_VALUE));
    }

    @Test
    public void changeLogs() throws Exception {
        LoggerVM logger = new LoggerVM();
        logger.setLevel("INFO");
        logger.setName("ROOT");

        restLogsMockMvc.perform(put("/management/logs")
            .contentType(TestUtil.APPLICATION_JSON_UTF8)
            .content(TestUtil.convertObjectToJsonBytes(logger)))
            .andExpect(status().isNoContent());
    }

    @Test
    public void testLogstashAppender() {
        LoggerContext context = (LoggerContext) LoggerFactory.getILoggerFactory();
        assertThat(context.getLogger("ROOT").getAppender("ASYNC_LOGSTASH")).isInstanceOf(AsyncAppender.class);
    }
}

 
 
package com.baeldung.jhipster.gateway.web.rest;

import com.baeldung.jhipster.gateway.GatewayApp;
import com.baeldung.jhipster.gateway.config.SecurityBeanOverrideConfiguration;
import com.baeldung.jhipster.gateway.web.rest.vm.LoggerVM;
import ch.qos.logback.classic.AsyncAppender;
import ch.qos.logback.classic.LoggerContext;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.LoggerFactory;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Test class for the LogsResource REST controller.
 *
 * @see LogsResource
 */
@RunWith(SpringRunner.class)
@SpringBootTest(classes = {SecurityBeanOverrideConfiguration.class, GatewayApp.class})
public class LogsResourceIntTest {

    private MockMvc restLogsMockMvc;

    @Before
    public void setup() {
        LogsResource logsResource = new LogsResource();
        this.restLogsMockMvc = MockMvcBuilders
            .standaloneSetup(logsResource)
            .build();
    }

    @Test
    public void getAllLogs() throws Exception {
        restLogsMockMvc.perform(get("/management/logs"))
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8_VALUE));
    }

    @Test
    public void changeLogs() throws Exception {
        LoggerVM logger = new LoggerVM();
        logger.setLevel("INFO");
        logger.setName("ROOT");

        restLogsMockMvc.perform(put("/management/logs")
            .contentType(TestUtil.APPLICATION_JSON_UTF8)
            .content(TestUtil.convertObjectToJsonBytes(logger)))
            .andExpect(status().isNoContent());
    }

    @Test
    public void testLogstashAppender() {
        LoggerContext context = (LoggerContext) LoggerFactory.getILoggerFactory();
        assertThat(context.getLogger("ROOT").getAppender("ASYNC_LOGSTASH")).isInstanceOf(AsyncAppender.class);
    }
}

 
 
package com.baeldung.jhipster.gateway.web.rest;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.hamcrest.Description;
import org.hamcrest.TypeSafeDiagnosingMatcher;
import org.springframework.format.datetime.standard.DateTimeFormatterRegistrar;
import org.springframework.format.support.DefaultFormattingConversionService;
import org.springframework.format.support.FormattingConversionService;
import org.springframework.http.MediaType;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.ZonedDateTime;
import java.time.format.DateTimeParseException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Utility class for testing REST controllers.
 */
public class TestUtil {

    /** MediaType for JSON UTF8 */
    public static final MediaType APPLICATION_JSON_UTF8 = new MediaType(
            MediaType.APPLICATION_JSON.getType(),
            MediaType.APPLICATION_JSON.getSubtype(), StandardCharsets.UTF_8);

    /**
     * Convert an object to JSON byte array.
     *
     * @param object
     *            the object to convert
     * @return the JSON byte array
     * @throws IOException
     */
    public static byte[] convertObjectToJsonBytes(Object object)
            throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        mapper.setSerializationInclusion(JsonInclude.Include.NON_EMPTY);

        JavaTimeModule module = new JavaTimeModule();
        mapper.registerModule(module);

        return mapper.writeValueAsBytes(object);
    }

    /**
     * Create a byte array with a specific size filled with specified data.
     *
     * @param size the size of the byte array
     * @param data the data to put in the byte array
     * @return the JSON byte array
     */
    public static byte[] createByteArray(int size, String data) {
        byte[] byteArray = new byte[size];
        for (int i = 0; i < size; i++) {
            byteArray[i] = Byte.parseByte(data, 2);
        }
        return byteArray;
    }

    /**
     * A matcher that tests that the examined string represents the same instant as the reference datetime.
     */
    public static class ZonedDateTimeMatcher extends TypeSafeDiagnosingMatcher<String> {

        private final ZonedDateTime date;

        public ZonedDateTimeMatcher(ZonedDateTime date) {
            this.date = date;
        }

        @Override
        protected boolean matchesSafely(String item, Description mismatchDescription) {
            try {
                if (!date.isEqual(ZonedDateTime.parse(item))) {
                    mismatchDescription.appendText("was ").appendValue(item);
                    return false;
                }
                return true;
            } catch (DateTimeParseException e) {
                mismatchDescription.appendText("was ").appendValue(item)
                    .appendText(", which could not be parsed as a ZonedDateTime");
                return false;
            }

        }

        @Override
        public void describeTo(Description description) {
            description.appendText("a String representing the same Instant as ").appendValue(date);
        }
    }

    /**
     * Creates a matcher that matches when the examined string reprensents the same instant as the reference datetime
     * @param date the reference datetime against which the examined string is checked
     */
    public static ZonedDateTimeMatcher sameInstant(ZonedDateTime date) {
        return new ZonedDateTimeMatcher(date);
    }

    /**
     * Verifies the equals/hashcode contract on the domain object.
     */
    public static <T> void equalsVerifier(Class<T> clazz) throws Exception {
        T domainObject1 = clazz.getConstructor().newInstance();
        assertThat(domainObject1.toString()).isNotNull();
        assertThat(domainObject1).isEqualTo(domainObject1);
        assertThat(domainObject1.hashCode()).isEqualTo(domainObject1.hashCode());
        // Test with an instance of another class
        Object testOtherObject = new Object();
        assertThat(domainObject1).isNotEqualTo(testOtherObject);
        assertThat(domainObject1).isNotEqualTo(null);
        // Test with an instance of the same class
        T domainObject2 = clazz.getConstructor().newInstance();
        assertThat(domainObject1).isNotEqualTo(domainObject2);
        // HashCodes are equals because the objects are not persisted yet
        assertThat(domainObject1.hashCode()).isEqualTo(domainObject2.hashCode());
    }

    /**
     * Create a FormattingConversionService which use ISO date format, instead of the localized one.
     * @return the FormattingConversionService
     */
    public static FormattingConversionService createFormattingConversionService() {
        DefaultFormattingConversionService dfcs = new DefaultFormattingConversionService ();
        DateTimeFormatterRegistrar registrar = new DateTimeFormatterRegistrar();
        registrar.setUseIsoFormat(true);
        registrar.registerFormatters(dfcs);
        return dfcs;
    }
}

 
 
package com.baeldung.jhipster.gateway.web.rest.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpHeaders;

/**
 * Tests based on parsing algorithm in app/components/util/pagination-util.service.js
 *
 * @see PaginationUtil
 */
public class PaginationUtilUnitTest {

    @Test
    public void generatePaginationHttpHeadersTest() {
        String baseUrl = "/api/_search/example";
        List<String> content = new ArrayList<>();
        Page<String> page = new PageImpl<>(content, PageRequest.of(6, 50), 400L);
        HttpHeaders headers = PaginationUtil.generatePaginationHttpHeaders(page, baseUrl);
        List<String> strHeaders = headers.get(HttpHeaders.LINK);
        assertNotNull(strHeaders);
        assertTrue(strHeaders.size() == 1);
        String headerData = strHeaders.get(0);
        assertTrue(headerData.split(",").length == 4);
        String expectedData = "</api/_search/example?page=7&size=50>; rel=\"next\","
                + "</api/_search/example?page=5&size=50>; rel=\"prev\","
                + "</api/_search/example?page=7&size=50>; rel=\"last\","
                + "</api/_search/example?page=0&size=50>; rel=\"first\"";
        assertEquals(expectedData, headerData);
        List<String> xTotalCountHeaders = headers.get("X-Total-Count");
        assertTrue(xTotalCountHeaders.size() == 1);
        assertTrue(Long.valueOf(xTotalCountHeaders.get(0)).equals(400L));
    }

}

 
package com.baeldung.jhipster.gateway.security.oauth2;

import com.baeldung.jhipster.gateway.config.oauth2.OAuth2Properties;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * Tests helper functions around OAuth2 Cookies.
 *
 * @see OAuth2CookieHelper
 */
public class OAuth2CookieHelperTest {
    public static final String GET_COOKIE_DOMAIN_METHOD = "getCookieDomain";
    private OAuth2Properties oAuth2Properties;
    private OAuth2CookieHelper cookieHelper;

    @Before
    public void setUp() throws NoSuchMethodException {
        oAuth2Properties = new OAuth2Properties();
        cookieHelper = new OAuth2CookieHelper(oAuth2Properties);
    }

    @Test
    public void testLocalhostDomain() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServerName("localhost");
        String name = ReflectionTestUtils.invokeMethod(cookieHelper, GET_COOKIE_DOMAIN_METHOD, request);
        Assert.assertNull(name);
    }

    @Test
    public void testComDomain() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServerName("test.com");
        String name = ReflectionTestUtils.invokeMethod(cookieHelper, GET_COOKIE_DOMAIN_METHOD, request);
        Assert.assertNull(name);        //already top-level domain
    }

    @Test
    public void testWwwDomainCom() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServerName("MailScanner has detected a possible fraud attempt from "www.test.com");ÂÂÂÂÂÂÂstringname=reflectiontestutils.invokemethod(cookiehelper,get_cookie_domain_method,request);ÂÂÂÂÂÂÂassert.assertnull(name);ÂÂÂ}ÂÂÂ@testÂÂÂpublicvoidtestcomsubdomain(){ÂÂÂÂÂÂÂmockhttpservletrequestrequest=newmockhttpservletrequest();ÂÂÂÂÂÂÂrequest.setservername("abc.test.com");ÂÂÂÂÂÂÂstringname=reflectiontestutils.invokemethod(cookiehelper,get_cookie_domain_method,request);ÂÂÂÂÂÂÂassert.assertequals(".test.com",name);ÂÂÂ}ÂÂÂ@testÂÂÂpublicvoidtestwwwsubdomaincom(){ÂÂÂÂÂÂÂmockhttpservletrequestrequest=newmockhttpservletrequest();ÂÂÂÂÂÂÂrequest.setservername("www.abc.test.com");ÂÂÂÂÂÂÂstringname=reflectiontestutils.invokemethod(cookiehelper,get_cookie_domain_method,request);ÂÂÂÂÂÂÂassert.assertequals(".test.com",name);ÂÂÂ}ÂÂÂ@testÂÂÂpublicvoidtestcoukdomain(){ÂÂÂÂÂÂÂmockhttpservletrequestrequest=newmockhttpservletrequest();ÂÂÂÂÂÂÂrequest.setservername("test.co.uk");ÂÂÂÂÂÂÂstringname=reflectiontestutils.invokemethod(cookiehelper,get_cookie_domain_method,request);ÂÂÂÂÂÂÂassert.assertnull(name);ÂÂÂÂÂÂÂÂÂÂÂ" claiming to be www.test.com");
        String name = ReflectionTestUtils.invokeMethod(cookieHelper, GET_COOKIE_DOMAIN_METHOD, request);
        Assert.assertNull(name);
    }

    @Test
    public void testComSubDomain() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServerName("abc.test.com");
        String name = ReflectionTestUtils.invokeMethod(cookieHelper, GET_COOKIE_DOMAIN_METHOD, request);
        Assert.assertEquals(".test.com", name);
    }

    @Test
    public void testWwwSubDomainCom() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServerName("www.abc.test.com");
        String name = ReflectionTestUtils.invokeMethod(cookieHelper, GET_COOKIE_DOMAIN_METHOD, request);
        Assert.assertEquals(".test.com", name);
    }


    @Test
    public void testCoUkDomain() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServerName("test.co.uk");
        String name = ReflectionTestUtils.invokeMethod(cookieHelper, GET_COOKIE_DOMAIN_METHOD, request);
        Assert.assertNull(name);            //already top-level domain
    }

    @Test
    public void testCoUkSubDomain() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServerName("abc.test.co.uk");
        String name = ReflectionTestUtils.invokeMethod(cookieHelper, GET_COOKIE_DOMAIN_METHOD, request);
        Assert.assertEquals(".test.co.uk", name);
    }

    @Test
    public void testNestedDomain() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServerName("abc.xyu.test.co.uk");
        String name = ReflectionTestUtils.invokeMethod(cookieHelper, GET_COOKIE_DOMAIN_METHOD, request);
        Assert.assertEquals(".test.co.uk", name);
    }

    @Test
    public void testIpAddress() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServerName("127.0.0.1");
        String name = ReflectionTestUtils.invokeMethod(cookieHelper, GET_COOKIE_DOMAIN_METHOD, request);
        Assert.assertNull(name);
    }
}

 
 
package com.baeldung.jhipster.gateway.security.oauth2;

import com.baeldung.jhipster.gateway.config.oauth2.OAuth2Properties;
import com.baeldung.jhipster.gateway.web.filter.RefreshTokenFilter;
import com.baeldung.jhipster.gateway.web.rest.errors.InvalidPasswordException;
import io.github.jhipster.config.JHipsterProperties;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.http.*;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.Mockito.when;

/**
 * Test password and refresh token grants.
 *
 * @see OAuth2AuthenticationService
 */
@RunWith(MockitoJUnitRunner.class)
public class OAuth2AuthenticationServiceTest {
    public static final String CLIENT_AUTHORIZATION = "Basic d2ViX2FwcDpjaGFuZ2VpdA==";
    public static final String ACCESS_TOKEN_VALUE = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0OTQyNzI4NDQsInVzZXJfbmFtZSI6InVzZXIiLCJhdXRob3JpdGllcyI6WyJST0xFX1VTRVIiXSwianRpIjoiNzc1ZTJkYWUtYWYzZi00YTdhLWExOTktNzNiZTU1MmIxZDVkIiwiY2xpZW50X2lkIjoid2ViX2FwcCIsInNjb3BlIjpbIm9wZW5pZCJdfQ.gEK0YcX2IpkpxnkxXXHQ4I0xzTjcy7edqb89ukYE0LPe7xUcZVwkkCJF_nBxsGJh2jtA6NzNLfY5zuL6nP7uoAq3fmvsyrcyR2qPk8JuuNzGtSkICx3kPDRjAT4ST8SZdeh7XCbPVbySJ7ZmPlRWHyedzLA1wXN0NUf8yZYS4ELdUwVBYIXSjkNoKqfWm88cwuNr0g0teypjPtjDqCnXFt1pibwdfIXn479Y1neNAdvSpHcI4Ost-c7APCNxW2gqX-0BItZQearxRgKDdBQ7CGPAIky7dA0gPuKUpp_VCoqowKCXqkE9yKtRQGIISewtj2UkDRZePmzmYrUBXRzfYw";
    public static final String REFRESH_TOKEN_VALUE = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX25hbWUiOiJ1c2VyIiwic2NvcGUiOlsib3BlbmlkIl0sImF0aSI6Ijc3NWUyZGFlLWFmM2YtNGE3YS1hMTk5LTczYmU1NTJiMWQ1ZCIsImV4cCI6MTQ5Njg2NDc0MywiYXV0aG9yaXRpZXMiOlsiUk9MRV9VU0VSIl0sImp0aSI6IjhmYjI2YTllLTdjYzQtNDFlMi1hNzBjLTk4MDc0N2U2YWFiOSIsImNsaWVudF9pZCI6IndlYl9hcHAifQ.q1-Df9_AFO6TJNiLKV2YwTjRbnd7qcXv52skXYnog5siHYRoR6cPtm6TNQ04iDAoIHljTSTNnD6DS3bHk41mV55gsSVxGReL8VCb_R8ZmhVL4-5yr90sfms0wFp6lgD2bPmZ-TXiS2Oe9wcbNWagy5RsEplZ-sbXu3tjmDao4FN35ojPsXmUs84XnNQH3Y_-PY9GjZG0JEfLQIvE0J5BkXS18Z015GKyA6GBIoLhAGBQQYyG9m10ld_a9fD5SmCyCF72Jad_pfP1u8Z_WyvO-wrlBvm2x-zBthreVrXU5mOb9795wJEP-xaw3dXYGjht_grcW4vKUFtj61JgZk98CQ";
    public static final String EXPIRED_SESSION_TOKEN_VALUE = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX25hbWUiOiJ1c2VyIiwic2NvcGUiOlsib3BlbmlkIl0sImF0aSI6IjE0NTkwYzdkLTQ5M2YtNDU0NS05MzlmLTg1ODM4ZjRmNzNmNSIsImV4cCI6MTQ5NTU3Mjg5MywiaWF0IjoxNDk1MzIwODkzLCJhdXRob3JpdGllcyI6WyJST0xFX1VTRVIiXSwianRpIjoiNzVhYTIxNzEtMzFmNi00MWJmLWExZGUtYWU0YTg1ZjZiMjEyIiwiY2xpZW50X2lkIjoid2ViX2FwcCJ9.gAH-yly7WAslQUeGhyHmjYXwQN3dluvoT84iOJ2mVWYGVlnDRsoxN3_d1ozqtiso9UM7dWpAr80o3gK7AyK-cO1GGBXa3lg0ETsbucFoqHLivgGZA2qVOsFlDq8E7DZENAbOWmywmhFUOogCfZ-BqsuFSi8waMLL-1qlhehBPuK1KzGxIZbjSVUFFFYTxoWPKi2NNTBzYSwwCV0ixj-gHyFC6Gl5ByA4EvYygGUZF2pACxs4tIRkmT90pXWCjWeKS9k9MlxZ7C4UHqyTRW-IYzqAm8OHdwsnXeu0GkFYc08gxoUuPcjMby8ziYLG5uWj0Ua0msmiSjoafzs-5xfH-Q";
    public static final String NEW_ACCESS_TOKEN_VALUE = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0OTQyNzY2NDEsInVzZXJfbmFtZSI6InVzZXIiLCJhdXRob3JpdGllcyI6WyJST0xFX1VTRVIiXSwianRpIjoiYzIyY2YzMDgtZTIyYi00YzNjLWI5MjctOTYwYzA2YmY1ZmU0IiwiY2xpZW50X2lkIjoid2ViX2FwcCIsInNjb3BlIjpbIm9wZW5pZCJdfQ.IAhE39GCqWRUuXdWy-raOcE9NYXRhGiqkeJH649501LeqNPH5HtRUNWmudVRgwT52Bj7HcbJapMLGetKIMEASqC1-WARfcZ_PR0r7Kfg3OlFALWOH_oVT5kvi2H-QCoSAF9mRYK6abCh_tPk5KryVB5c7YxTMIXDT2nTsSexD8eNQOMBWRCg0RaLHZ9bKfeyVgncQJsu7-vTo1xJyh-keYpdNZ0TA2SjYJgezmB7gwW1Kmc7_83htr8VycG7XA_PuD9--yRNlrN0LtNHEBqNypZsOe6NvpKiNlodFYHlsU1CaumzcF9U7dpVanjIUKJ5VRWVUlSFY6JJ755W29VCTw";
    public static final String NEW_REFRESH_TOKEN_VALUE = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX25hbWUiOiJ1c2VyIiwic2NvcGUiOlsib3BlbmlkIl0sImF0aSI6ImMyMmNmMzA4LWUyMmItNGMzYy1iOTI3LTk2MGMwNmJmNWZlNCIsImV4cCI6MTQ5Njg2ODU4MSwiYXV0aG9yaXRpZXMiOlsiUk9MRV9VU0VSIl0sImp0aSI6ImU4YmZhZWJlLWYzMDItNGNjZS1hZGY1LWQ4MzE5OWM1MjBlOSIsImNsaWVudF9pZCI6IndlYl9hcHAifQ.OemWBUfc-2rl4t4VVqolYxul3L527PbSbX2Xvo7oyy3Vy5nmmblqp4hVGdTEjivrlldGVQX03ERbrA-oFkpmfWbBzLvnKS6AUq1MGjut6dXZJeiEqNYmiAABn6jSgK26S0k6b2ADgmf7mxJO8EBypb5sT1DMAbY5cbOe7r4ZG7zMTVSvlvjHTXp_FM8Y9i6nehLD4XDYY57cb_ZA89vAXNzvTAjoopDliExgR0bApG6nvvDEhEYgTS65lccEQocoev6bISJ3RvNYNPJxWcNPftKDp4HrEt2E2WP28K5IivRtQgDQNlQeormf1tp6AG-Oj__NXyAPM7yhAKXNy2zWdQ";
    @Mock
    private RestTemplate restTemplate;
    @Mock
    private TokenStore tokenStore;
    private OAuth2TokenEndpointClient authorizationClient;
    private OAuth2AuthenticationService authenticationService;
    private RefreshTokenFilter refreshTokenFilter;
    @Rule
    public ExpectedException expectedException = ExpectedException.none();
    private OAuth2Properties oAuth2Properties;
    private JHipsterProperties jHipsterProperties;

    @Before
    public void init() {
        oAuth2Properties = new OAuth2Properties();
        jHipsterProperties = new JHipsterProperties();
        jHipsterProperties.getSecurity().getClientAuthorization().setAccessTokenUri("http://uaa/oauth/token");
        OAuth2CookieHelper cookieHelper = new OAuth2CookieHelper(oAuth2Properties);
        OAuth2AccessToken accessToken = createAccessToken(ACCESS_TOKEN_VALUE, REFRESH_TOKEN_VALUE);

        mockInvalidPassword();
        mockPasswordGrant(accessToken);
        mockRefreshGrant();

        authorizationClient = new UaaTokenEndpointClient(restTemplate, jHipsterProperties, oAuth2Properties);
        authenticationService = new OAuth2AuthenticationService(authorizationClient, cookieHelper);
        when(tokenStore.readAccessToken(ACCESS_TOKEN_VALUE)).thenReturn(accessToken);
        refreshTokenFilter = new RefreshTokenFilter(authenticationService, tokenStore);
    }

    public static OAuth2AccessToken createAccessToken(String accessTokenValue, String refreshTokenValue) {
        DefaultOAuth2AccessToken accessToken = new DefaultOAuth2AccessToken(accessTokenValue);
        accessToken.setExpiration(new Date());          //token expires now
        DefaultOAuth2RefreshToken refreshToken = new DefaultOAuth2RefreshToken(refreshTokenValue);
        accessToken.setRefreshToken(refreshToken);
        return accessToken;
    }

    public static MockHttpServletRequest createMockHttpServletRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest(HttpMethod.GET.name(), "http://www.test.com");
        Cookie accessTokenCookie = new Cookie(OAuth2CookieHelper.ACCESS_TOKEN_COOKIE, ACCESS_TOKEN_VALUE);
        Cookie refreshTokenCookie = new Cookie(OAuth2CookieHelper.REFRESH_TOKEN_COOKIE, REFRESH_TOKEN_VALUE);
        request.setCookies(accessTokenCookie, refreshTokenCookie);
        return request;
    }

    private void mockInvalidPassword() {
        HttpHeaders reqHeaders = new HttpHeaders();
        reqHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        reqHeaders.add("Authorization", CLIENT_AUTHORIZATION);                //take over Authorization header from client request to UAA request
        MultiValueMap<String, String> formParams = new LinkedMultiValueMap<>();
        formParams.set("username", "user");
        formParams.set("password", "user2");
        formParams.add("grant_type", "password");
        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(formParams, reqHeaders);
        when(restTemplate.postForEntity("http://uaa/oauth/token", entity, OAuth2AccessToken.class))
            .thenThrow(new HttpClientErrorException(HttpStatus.BAD_REQUEST));
    }

    private void mockPasswordGrant(OAuth2AccessToken accessToken) {
        HttpHeaders reqHeaders = new HttpHeaders();
        reqHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        reqHeaders.add("Authorization", CLIENT_AUTHORIZATION);                //take over Authorization header from client request to UAA request
        MultiValueMap<String, String> formParams = new LinkedMultiValueMap<>();
        formParams.set("username", "user");
        formParams.set("password", "user");
        formParams.add("grant_type", "password");
        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(formParams, reqHeaders);
        when(restTemplate.postForEntity("http://uaa/oauth/token", entity, OAuth2AccessToken.class))
            .thenReturn(new ResponseEntity<OAuth2AccessToken>(accessToken, HttpStatus.OK));
    }

    private void mockRefreshGrant() {
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "refresh_token");
        params.add("refresh_token", REFRESH_TOKEN_VALUE);
        //we must authenticate with the UAA server via HTTP basic authentication using the browser's client_id with no client secret
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", CLIENT_AUTHORIZATION);
        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(params, headers);
        OAuth2AccessToken newAccessToken = createAccessToken(NEW_ACCESS_TOKEN_VALUE, NEW_REFRESH_TOKEN_VALUE);
        when(restTemplate.postForEntity("http://uaa/oauth/token", entity, OAuth2AccessToken.class))
            .thenReturn(new ResponseEntity<OAuth2AccessToken>(newAccessToken, HttpStatus.OK));
    }

    @Test
    public void testAuthenticationCookies() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServerName("www.test.com");
        request.addHeader("Authorization", CLIENT_AUTHORIZATION);
        Map<String, String> params = new HashMap<>();
        params.put("username", "user");
        params.put("password", "user");
        params.put("rememberMe", "true");
        MockHttpServletResponse response = new MockHttpServletResponse();
        authenticationService.authenticate(request, response, params);
        //check that cookies are set correctly
        Cookie accessTokenCookie = response.getCookie(OAuth2CookieHelper.ACCESS_TOKEN_COOKIE);
        Assert.assertEquals(ACCESS_TOKEN_VALUE, accessTokenCookie.getValue());
        Cookie refreshTokenCookie = response.getCookie(OAuth2CookieHelper.REFRESH_TOKEN_COOKIE);
        Assert.assertEquals(REFRESH_TOKEN_VALUE, OAuth2CookieHelper.getRefreshTokenValue(refreshTokenCookie));
        Assert.assertTrue(OAuth2CookieHelper.isRememberMe(refreshTokenCookie));
    }

    @Test
    public void testAuthenticationNoRememberMe() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServerName("www.test.com");
        Map<String, String> params = new HashMap<>();
        params.put("username", "user");
        params.put("password", "user");
        params.put("rememberMe", "false");
        MockHttpServletResponse response = new MockHttpServletResponse();
        authenticationService.authenticate(request, response, params);
        //check that cookies are set correctly
        Cookie accessTokenCookie = response.getCookie(OAuth2CookieHelper.ACCESS_TOKEN_COOKIE);
        Assert.assertEquals(ACCESS_TOKEN_VALUE, accessTokenCookie.getValue());
        Cookie refreshTokenCookie = response.getCookie(OAuth2CookieHelper.SESSION_TOKEN_COOKIE);
        Assert.assertEquals(REFRESH_TOKEN_VALUE, OAuth2CookieHelper.getRefreshTokenValue(refreshTokenCookie));
        Assert.assertFalse(OAuth2CookieHelper.isRememberMe(refreshTokenCookie));
    }

    @Test
    public void testInvalidPassword() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServerName("www.test.com");
        Map<String, String> params = new HashMap<>();
        params.put("username", "user");
        params.put("password", "user2");
        params.put("rememberMe", "false");
        MockHttpServletResponse response = new MockHttpServletResponse();
        expectedException.expect(InvalidPasswordException.class);
        authenticationService.authenticate(request, response, params);
    }

    @Test
    public void testRefreshGrant() {
        MockHttpServletRequest request = createMockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        HttpServletRequest newRequest = refreshTokenFilter.refreshTokensIfExpiring(request, response);
        Cookie newAccessTokenCookie = response.getCookie(OAuth2CookieHelper.ACCESS_TOKEN_COOKIE);
        Assert.assertEquals(NEW_ACCESS_TOKEN_VALUE, newAccessTokenCookie.getValue());
        Cookie newRefreshTokenCookie = response.getCookie(OAuth2CookieHelper.REFRESH_TOKEN_COOKIE);
        Assert.assertEquals(NEW_REFRESH_TOKEN_VALUE, newRefreshTokenCookie.getValue());
        Cookie requestAccessTokenCookie = OAuth2CookieHelper.getAccessTokenCookie(newRequest);
        Assert.assertEquals(NEW_ACCESS_TOKEN_VALUE, requestAccessTokenCookie.getValue());
    }

    @Test
    public void testSessionExpired() {
        MockHttpServletRequest request = new MockHttpServletRequest(HttpMethod.GET.name(), "http://www.test.com");
        Cookie accessTokenCookie = new Cookie(OAuth2CookieHelper.ACCESS_TOKEN_COOKIE, ACCESS_TOKEN_VALUE);
        Cookie refreshTokenCookie = new Cookie(OAuth2CookieHelper.SESSION_TOKEN_COOKIE, EXPIRED_SESSION_TOKEN_VALUE);
        request.setCookies(accessTokenCookie, refreshTokenCookie);
        MockHttpServletResponse response = new MockHttpServletResponse();
        HttpServletRequest newRequest = refreshTokenFilter.refreshTokensIfExpiring(request, response);
        //cookies in response are deleted
        Cookie newAccessTokenCookie = response.getCookie(OAuth2CookieHelper.ACCESS_TOKEN_COOKIE);
        Assert.assertEquals(0, newAccessTokenCookie.getMaxAge());
        Cookie newRefreshTokenCookie = response.getCookie(OAuth2CookieHelper.REFRESH_TOKEN_COOKIE);
        Assert.assertEquals(0, newRefreshTokenCookie.getMaxAge());
        //request no longer contains cookies
        Cookie requestAccessTokenCookie = OAuth2CookieHelper.getAccessTokenCookie(newRequest);
        Assert.assertNull(requestAccessTokenCookie);
        Cookie requestRefreshTokenCookie = OAuth2CookieHelper.getRefreshTokenCookie(newRequest);
        Assert.assertNull(requestRefreshTokenCookie);
    }

    /**
     * If no refresh token is found and the access token has expired, then expect an exception.
     */
    @Test
    public void testRefreshGrantNoRefreshToken() {
        MockHttpServletRequest request = new MockHttpServletRequest(HttpMethod.GET.name(), "http://www.test.com");
        Cookie accessTokenCookie = new Cookie(OAuth2CookieHelper.ACCESS_TOKEN_COOKIE, ACCESS_TOKEN_VALUE);
        request.setCookies(accessTokenCookie);
        MockHttpServletResponse response = new MockHttpServletResponse();
        expectedException.expect(InvalidTokenException.class);
        refreshTokenFilter.refreshTokensIfExpiring(request, response);
    }

    @Test
    public void testLogout() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        Cookie accessTokenCookie = new Cookie(OAuth2CookieHelper.ACCESS_TOKEN_COOKIE, ACCESS_TOKEN_VALUE);
        Cookie refreshTokenCookie = new Cookie(OAuth2CookieHelper.REFRESH_TOKEN_COOKIE, REFRESH_TOKEN_VALUE);
        request.setCookies(accessTokenCookie, refreshTokenCookie);
        MockHttpServletResponse response = new MockHttpServletResponse();
        authenticationService.logout(request, response);
        Cookie newAccessTokenCookie = response.getCookie(OAuth2CookieHelper.ACCESS_TOKEN_COOKIE);
        Assert.assertEquals(0, newAccessTokenCookie.getMaxAge());
        Cookie newRefreshTokenCookie = response.getCookie(OAuth2CookieHelper.REFRESH_TOKEN_COOKIE);
        Assert.assertEquals(0, newRefreshTokenCookie.getMaxAge());
    }

    @Test
    public void testStripTokens() {
        MockHttpServletRequest request = createMockHttpServletRequest();
        HttpServletRequest newRequest = authenticationService.stripTokens(request);
        CookieCollection cookies = new CookieCollection(newRequest.getCookies());
        Assert.assertFalse(cookies.contains(OAuth2CookieHelper.ACCESS_TOKEN_COOKIE));
        Assert.assertFalse(cookies.contains(OAuth2CookieHelper.REFRESH_TOKEN_COOKIE));
    }
}

 
 
 
 
package com.baeldung.jhipster.gateway.security.oauth2;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

/**
 * Test whether the CookieTokenExtractor can properly extract access tokens from
 * Cookies and Headers.
 */
public class CookieTokenExtractorTest {
    private CookieTokenExtractor cookieTokenExtractor;

    @Before
    public void init() {
        cookieTokenExtractor = new CookieTokenExtractor();
    }

    @Test
    public void testExtractTokenCookie() {
        MockHttpServletRequest request = OAuth2AuthenticationServiceTest.createMockHttpServletRequest();
        Authentication authentication = cookieTokenExtractor.extract(request);
        Assert.assertEquals(OAuth2AuthenticationServiceTest.ACCESS_TOKEN_VALUE, authentication.getPrincipal().toString());
    }

    @Test
    public void testExtractTokenHeader() {
        MockHttpServletRequest request = new MockHttpServletRequest(HttpMethod.GET.name(), "http://www.test.com");
        request.addHeader("Authorization", OAuth2AccessToken.BEARER_TYPE + " " + OAuth2AuthenticationServiceTest.ACCESS_TOKEN_VALUE);
        Authentication authentication = cookieTokenExtractor.extract(request);
        Assert.assertEquals(OAuth2AuthenticationServiceTest.ACCESS_TOKEN_VALUE, authentication.getPrincipal().toString());
    }

    @Test
    public void testExtractTokenParam() {
        MockHttpServletRequest request = new MockHttpServletRequest(HttpMethod.GET.name(), "http://www.test.com");
        request.addParameter(OAuth2AccessToken.ACCESS_TOKEN, OAuth2AuthenticationServiceTest.ACCESS_TOKEN_VALUE);
        Authentication authentication = cookieTokenExtractor.extract(request);
        Assert.assertEquals(OAuth2AuthenticationServiceTest.ACCESS_TOKEN_VALUE, authentication.getPrincipal().toString());
    }
}

 
https://blog.csdn.net/liusanyu/article/details/78840483
 
 
@RunWith(SpringRunner.class)
@DataJpaTest
@AutoConfigureEmbeddedDatabase
public class SpringDataJpaAnnotationTest {

    @Autowired
    private PersonRepository personRepository;

    @Test
    public void testEmbeddedDatabase() {
        Optional<Person> personOptional = personRepository.findById(1L);

        assertThat(personOptional).hasValueSatisfying(person -> {
            assertThat(person.getId()).isNotNull();
            assertThat(person.getFirstName()).isEqualTo("Dave");
            assertThat(person.getLastName()).isEqualTo("Syer");
        });
    }
}

Standard Dockerfile
FROM openjdk:8-jdk

RUN groupadd --system --gid 1000 test
RUN useradd --system --gid test --uid 1000 --shell /bin/bash --create-home test

USER test
WORKDIR /home/test
Alpine Dockerfile
FROM openjdk:8-jdk-alpine

RUN addgroup -S -g 1000 test
RUN adduser -D -S -G test -u 1000 -s /bin/ash test

USER test
WORKDIR /home/test
--------------------------------------------------------------------------------------------------------
@Configuration
@ConditionalOnExpression(
    "${module.enabled:true} and ${module.submodule.enabled:true}"
)
class SubModule {
  ...
}
--------------------------------------------------------------------------------------------------------
@SpringBootApplication
public class SpringBootComponentScanApp {
    private static ApplicationContext applicationContext;
 
    @Bean
    public ExampleBean exampleBean() {
        return new ExampleBean();
    }
 
    public static void main(String[] args) {
        applicationContext = SpringApplication.run(SpringBootComponentScanApp.class, args);
        checkBeansPresence("cat", "dog", "rose", "exampleBean", "springBootComponentScanApp");
 
    }
 
    private static void checkBeansPresence(String... beans) {
        for (String beanName : beans) {
            System.out.println("Is " + beanName + " in ApplicationContext: " + 
              applicationContext.containsBean(beanName));
        }
    }
}
--------------------------------------------------------------------------------------------------------
var oauthToken = null;

function login() {
    var userLogin = $('#loginField').val();
    var userPassword = $('#passwordField').val();
    console.log ( '#someButton was clicked' );
    $.post({
        url: 'http://localhost:8080/app/rest/v2/oauth/token',
        headers: {
            'Authorization': 'Basic Y2xpZW50OnNlY3JldA==',
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        dataType: 'json',
        data: {grant_type: 'password', username: userLogin, password: userPassword},
        success: function (data) {
            oauthToken = data.access_token;
            $('#loggedInStatus').show();
            $('#loginForm').hide();
            loadRecentOrders();
        }
    })
}

function loadRecentOrders() {
    $.get({
        url: 'http://localhost:8080/app/rest/v2/entities/workshop$Order?view=_local',
        headers: {
            'Authorization': 'Bearer ' + oauthToken,
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        success: function (data) {
            $('#recentOrders').show();
            $.each(data, function (i, order) {
                $('#ordersList').append("<li>" + order.description + "</li>");
            });
        }
    });
}

@ConfigurationProperties("app.system")
public class AppSystemProperties {

	@DurationUnit(ChronoUnit.SECONDS)
	private Duration sessionTimeout = Duration.ofSeconds(30);

	private Duration readTimeout = Duration.ofMillis(1000);

	public Duration getSessionTimeout() {
		return this.sessionTimeout;
	}

	public void setSessionTimeout(Duration sessionTimeout) {
		this.sessionTimeout = sessionTimeout;
	}

	public Duration getReadTimeout() {
		return this.readTimeout;
	}

	public void setReadTimeout(Duration readTimeout) {
		this.readTimeout = readTimeout;
	}

}
@ConfigurationProperties("app.io")
public class AppIoProperties {

	@DataSizeUnit(DataUnit.MEGABYTES)
	private DataSize bufferSize = DataSize.ofMegabytes(2);

	private DataSize sizeThreshold = DataSize.ofBytes(512);

	public DataSize getBufferSize() {
		return this.bufferSize;
	}

	public void setBufferSize(DataSize bufferSize) {
		this.bufferSize = bufferSize;
	}

	public DataSize getSizeThreshold() {
		return this.sizeThreshold;
	}

	public void setSizeThreshold(DataSize sizeThreshold) {
		this.sizeThreshold = sizeThreshold;
	}
}
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
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;

import java.io.IOException;
import java.util.Arrays;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SingleAppResourcePatternResolver extends PathMatchingResourcePatternResolver {

    public static final Pattern JAR_NAME_PATTERN = Pattern.compile(".*/(.+?\\.jar).*");

    private Set<String> dependencyJars;

    public SingleAppResourcePatternResolver(ResourceLoader resourceLoader, Set<String> dependencyJars) {
        super(resourceLoader);
        this.dependencyJars = dependencyJars;
    }

    @Override
    public Resource[] getResources(String locationPattern) throws IOException {
        Resource[] resources = super.getResources(locationPattern);
        return Arrays.stream(resources)
                .filter(this::foundInDependencies)
                .toArray(Resource[]::new);
    }

    private boolean foundInDependencies(Resource resource) {
        try {
            String url = resource.getURL().toString();
            if (url.contains("META-INF/resources/webjars/")) {
                // WebJAR resources could be loaded from shared dependencies
                return true;
            }

            Matcher matcher = JAR_NAME_PATTERN.matcher(url);
            if (matcher.find()) {
                String jarName = matcher.group(1);
                return dependencyJars.contains(jarName);
            }
            return true;
        } catch (IOException e) {
            throw new RuntimeException("An error occurred while looking for resources", e);
        }
    }
}
--------------------------------------------------------------------------------------------------------
import javax.annotation.Nullable;
import java.util.*;

/**
 * Describes an app component which the current application depends on.
 */
public class AppComponent implements Comparable<AppComponent> {

    private final String id;
    private final List<AppComponent> dependencies = new ArrayList<>();
    private Properties properties;
    private Set<String> additiveProperties;

    public AppComponent(String id) {
        this.id = id;
    }

    /**
     * @return app component Id
     */
    public String getId() {
        return id;
    }

    /**
     * @return descriptor path by convention
     */
    public String getDescriptorPath() {
        return id.replace('.', '/') + "/app-component.xml";
    }

    /**
     * INTERNAL.
     * Add a dependency to the component.
     */
    public void addDependency(AppComponent other) {
        if (dependencies.contains(other))
            return;
        if (other.dependsOn(this))
            throw new RuntimeException("Circular dependency between app components '" + this + "' and '" + other + "'");

        dependencies.add(other);
    }

    /**
     * Check if this component depends on the given component.
     */
    public boolean dependsOn(AppComponent other) {
        for (AppComponent dependency : dependencies) {
            if (dependency.equals(other) || dependency.dependsOn(other))
                return true;
        }
        return false;
    }

    /**
     * INTERNAL.
     * Set a file-based app property defined in this app component.
     */
    public void setProperty(String name, String value, boolean additive) {
        if (properties == null)
            properties = new Properties();

        if (additive) {
            if (additiveProperties == null) {
                additiveProperties = new HashSet<>();
            }
            additiveProperties.add(name);
        } else if (additiveProperties != null) {
            additiveProperties.remove(name);
        }

        properties.setProperty(name, value);
    }

    /**
     * @return a file-based app property defined in this app component or null if not found
     */
    @Nullable
    public String getProperty(String property) {
        return properties == null ? null : properties.getProperty(property);
    }

    public boolean isAdditiveProperty(String property) {
        return additiveProperties != null && additiveProperties.contains(property);
    }

    /**
     * @return names of properties exported by this app component, sorted in natural order
     */
    public List<String> getPropertyNames() {
        if (properties == null) {
            return Collections.emptyList();
        }
        List<String> list = new ArrayList<>(properties.stringPropertyNames());
        list.sort(Comparator.naturalOrder());
        return list;
    }

    @Override
    public int compareTo(AppComponent other) {
        if (this.dependsOn(other))
            return 1;
        if (other.dependsOn(this)) {
            return -1;
        }
        return 0;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        AppComponent that = (AppComponent) o;

        return id.equals(that.id);

    }

    @Override
    public int hashCode() {
        return id.hashCode();
    }

    @Override
    public String toString() {
        return id;
    }
}
--------------------------------------------------------------------------------------------------------
import com.haulmont.cuba.core.global.MessageTools;
import com.haulmont.cuba.core.global.Messages;
import org.hibernate.validator.internal.engine.messageinterpolation.InterpolationTerm;
import org.hibernate.validator.internal.engine.messageinterpolation.InterpolationTermType;
import org.hibernate.validator.internal.engine.messageinterpolation.parser.Token;
import org.hibernate.validator.internal.engine.messageinterpolation.parser.TokenCollector;
import org.hibernate.validator.internal.engine.messageinterpolation.parser.TokenIterator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.el.ExpressionFactory;
import javax.validation.MessageInterpolator;
import javax.validation.ValidationException;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CubaValidationMessagesInterpolator implements MessageInterpolator {
    protected static final String DEFAULT_CONSTRAINTS_MESSAGE_PACK = "com.haulmont.cuba.core.global.validation";

    private final Logger log = LoggerFactory.getLogger(CubaValidationMessagesInterpolator.class);

    protected Messages messages;
    protected ExpressionFactory expressionFactory;
    protected Locale locale;

    protected static final Pattern LEFT_BRACE = Pattern.compile("\\{", Pattern.LITERAL);
    protected static final Pattern RIGHT_BRACE = Pattern.compile("\\}", Pattern.LITERAL);
    protected static final Pattern SLASH = Pattern.compile("\\\\", Pattern.LITERAL);
    protected static final Pattern DOLLAR = Pattern.compile("\\$", Pattern.LITERAL);

    public CubaValidationMessagesInterpolator(Messages messages, Locale locale) {
        this.messages = messages;
        this.locale = locale;
        this.expressionFactory = ExpressionFactory.newInstance();
    }

    @Override
    public String interpolate(String messageTemplate, Context context) {
        Locale defaultLocale = locale;
        return interpolate(messageTemplate, context, defaultLocale);
    }

    @Override
    public String interpolate(String messageTemplate, Context context, Locale locale) {
        String interpolatedMessage = messageTemplate;
        try {
            interpolatedMessage = interpolateMessage(messageTemplate, context, locale);
        } catch (ValidationException e) {
            log.error("Unable to interpolate validation message: {}", e.getMessage());
        }
        return interpolatedMessage;
    }

    protected String interpolateMessage(String messageTemplate, Context context, Locale locale) {
        String resolvedMessage = interpolateMessage(messageTemplate, locale);

        TokenCollector tokenCollector = new TokenCollector(resolvedMessage, InterpolationTermType.PARAMETER);
        List<Token> tokens = tokenCollector.getTokenList();

        resolvedMessage = interpolateExpression(new TokenIterator(tokens), context, locale);

        tokenCollector = new TokenCollector(resolvedMessage, InterpolationTermType.EL);
        tokens = tokenCollector.getTokenList();

        resolvedMessage = interpolateExpression(new TokenIterator(tokens), context, locale);

        resolvedMessage = replaceEscapedLiterals(resolvedMessage);

        return resolvedMessage;
    }

    protected String interpolateExpression(TokenIterator tokenIterator, Context context, Locale locale) {
        while (tokenIterator.hasMoreInterpolationTerms()) {
            String term = tokenIterator.nextInterpolationTerm();

            InterpolationTerm expression = new InterpolationTerm(term, locale, expressionFactory);
            String resolvedExpression = expression.interpolate(context);
            tokenIterator.replaceCurrentInterpolationTerm(resolvedExpression);
        }
        return tokenIterator.getInterpolatedMessage();
    }

    protected String replaceEscapedLiterals(String resolvedMessage) {
        resolvedMessage = LEFT_BRACE.matcher(resolvedMessage).replaceAll("{");
        resolvedMessage = RIGHT_BRACE.matcher(resolvedMessage).replaceAll("}");
        resolvedMessage = SLASH.matcher(resolvedMessage).replaceAll(Matcher.quoteReplacement("\\"));
        resolvedMessage = DOLLAR.matcher(resolvedMessage).replaceAll(Matcher.quoteReplacement("$"));
        return resolvedMessage;
    }

    protected String interpolateMessage(String message, Locale locale) {
        TokenCollector tokenCollector = new TokenCollector(message, InterpolationTermType.PARAMETER);
        TokenIterator tokenIterator = new TokenIterator(tokenCollector.getTokenList());
        while (tokenIterator.hasMoreInterpolationTerms()) {
            String term = tokenIterator.nextInterpolationTerm();
            String resolvedParameterValue = resolveParameter(term, locale);
            tokenIterator.replaceCurrentInterpolationTerm(resolvedParameterValue);
        }
        return tokenIterator.getInterpolatedMessage();
    }

    protected String resolveParameter(String parameterName, Locale locale) {
        String parameterValue;
        String messageCode = removeCurlyBraces(parameterName);
        try {
            if (messageCode.startsWith("javax.validation.constraints")
                    || messageCode.startsWith("org.hibernate.validator.constraints")) {
                parameterValue = messages.getMessage(DEFAULT_CONSTRAINTS_MESSAGE_PACK, messageCode, locale);
                // try to find tokens recursive
                parameterValue = interpolateMessage(parameterValue, locale);
            } else if (messageCode.startsWith(MessageTools.MARK) || messageCode.startsWith(MessageTools.MAIN_MARK)) {
                parameterValue = messages.getTools().loadString(messageCode, locale);
                // try to find tokens recursive
                parameterValue = interpolateMessage(parameterValue, locale);
            } else {
                parameterValue = parameterName;
            }
        } catch (UnsupportedOperationException e) {
            // return parameter itself
            parameterValue = parameterName;
        }
        return parameterValue;
    }

    protected String removeCurlyBraces(String parameter) {
        return parameter.substring(1, parameter.length() - 1);
    }
}
--------------------------------------------------------------------------------------------------------
import com.haulmont.cuba.core.global.EntityStates;
import com.haulmont.cuba.core.global.Metadata;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.validation.Path;
import javax.validation.TraversableResolver;
import java.lang.annotation.ElementType;

public class CubaValidationTraversableResolver implements TraversableResolver {

    private static final Logger log = LoggerFactory.getLogger(CubaValidationTraversableResolver.class);

    protected Metadata metadata;
    protected EntityStates entityStates;

    public CubaValidationTraversableResolver(Metadata metadata, EntityStates entityStates) {
        this.metadata = metadata;
        this.entityStates = entityStates;
    }

    @Override
    public final boolean isReachable(Object traversableObject,
                                     Path.Node traversableProperty,
                                     Class<?> rootBeanType,
                                     Path pathToTraversableObject,
                                     ElementType elementType) {
        log.trace("Calling isReachable on object {} with node name {}",
                traversableObject, traversableProperty.getName());

        if (traversableObject == null
                || metadata.getClass(traversableObject.getClass()) == null) {
            return true;
        }

        return entityStates.isLoaded(traversableObject, traversableProperty.getName());
    }

    @Override
    public boolean isCascadable(Object traversableObject, Path.Node traversableProperty, Class<?> rootBeanType,
                                Path pathToTraversableObject, ElementType elementType) {
        // return true as org.hibernate.validator.internal.engine.resolver.JPATraversableResolver does
        return true;
    }
}
--------------------------------------------------------------------------------------------------------
import javax.validation.ClockProvider;
import java.time.Clock;
import java.time.ZonedDateTime;

public class CubaValidationTimeProvider implements ClockProvider {

    protected TimeSource timeSource;

    public CubaValidationTimeProvider(TimeSource timeSource) {
        this.timeSource = timeSource;
    }

    @Override
    public Clock getClock() {
        ZonedDateTime now = timeSource.now();
        return Clock.fixed(now.toInstant(), now.getZone());
    }
}
--------------------------------------------------------------------------------------------------------
import com.haulmont.cuba.core.global.*;
import com.haulmont.cuba.core.sys.validation.CubaValidationMessagesInterpolator;
import com.haulmont.cuba.core.sys.validation.CubaValidationTimeProvider;
import com.haulmont.cuba.core.sys.validation.CubaValidationTraversableResolver;
import org.hibernate.validator.HibernateValidator;
import org.hibernate.validator.HibernateValidatorConfiguration;
import org.hibernate.validator.cfg.ConstraintMapping;
import org.springframework.stereotype.Component;

import javax.annotation.Nullable;
import javax.inject.Inject;
import javax.validation.Validation;
import javax.validation.Validator;
import javax.validation.ValidatorFactory;
import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;

import static com.haulmont.bali.util.Preconditions.checkNotNullArgument;

@Component(BeanValidation.NAME)
public class BeanValidationImpl implements BeanValidation {

    public static final ValidationOptions NO_VALIDATION_OPTIONS = new ValidationOptions();

    @Inject
    protected Messages messages;
    @Inject
    protected Metadata metadata;
    @Inject
    protected TimeSource timeSource;
    @Inject
    protected UserSessionSource userSessionSource;
    @Inject
    protected EntityStates entityStates;

    protected ConcurrentHashMap<Locale, ValidatorFactory> validatorFactoriesCache = new ConcurrentHashMap<>();

    @Override
    public Validator getValidator() {
        Locale locale = getCurrentLocale();

        return getValidatorWithDefaultFactory(locale);
    }

    @Override
    public Validator getValidator(ConstraintMapping constraintMapping) {
        checkNotNullArgument(constraintMapping);

        return getValidator(constraintMapping, NO_VALIDATION_OPTIONS);
    }

    @Override
    public Validator getValidator(@Nullable ConstraintMapping constraintMapping, ValidationOptions options) {
        checkNotNullArgument(options);

        if (constraintMapping == null
                && options.getFailFast() == null
                && options.getLocale() != null) {
            return getValidatorWithDefaultFactory(options.getLocale());
        }

        Locale locale;
        if (options.getLocale() != null) {
            locale = options.getLocale();
        } else {
            locale = getCurrentLocale();
        }

        HibernateValidatorConfiguration configuration = getValidatorFactoryConfiguration(locale);
        if (options.getFailFast() != null) {
            configuration.failFast(options.getFailFast());
        }
        if (constraintMapping != null) {
            configuration.addMapping(constraintMapping);
        }

        ValidatorFactory factory = configuration.buildValidatorFactory();
        return factory.getValidator();
    }

    protected Validator getValidatorWithDefaultFactory(Locale locale) {
        ValidatorFactory validatorFactoryFromCache = validatorFactoriesCache.get(locale);
        if (validatorFactoryFromCache != null) {
            return validatorFactoryFromCache.getValidator();
        }

        HibernateValidatorConfiguration configuration = getValidatorFactoryConfiguration(locale);
        ValidatorFactory factory = configuration.buildValidatorFactory();

        validatorFactoriesCache.put(locale, factory);

        return factory.getValidator();
    }

    protected HibernateValidatorConfiguration getValidatorFactoryConfiguration(Locale locale) {
        @SuppressWarnings("UnnecessaryLocalVariable")
        HibernateValidatorConfiguration configuration = Validation.byProvider(HibernateValidator.class)
                .configure()
                .clockProvider(new CubaValidationTimeProvider(timeSource))
                .traversableResolver(new CubaValidationTraversableResolver(metadata, entityStates))
                .messageInterpolator(new CubaValidationMessagesInterpolator(messages, locale));

        return configuration;
    }

    protected Locale getCurrentLocale() {
        Locale locale;
        if (userSessionSource.checkCurrentUserSession()) {
            locale = userSessionSource.getLocale();
        } else {
            locale = messages.getTools().getDefaultLocale();
        }
        return locale;
    }
}
=======
LinkedMultiValueMap<String, Object> map = new LinkedMultiValueMap<>();
map.add("file", new ClassPathResource(file));
HttpHeaders headers = new HttpHeaders();
headers.setContentType(MediaType.MULTIPART_FORM_DATA);

HttpEntity<LinkedMultiValueMap<String, Object>> requestEntity = new    HttpEntity<LinkedMultiValueMap<String, Object>>(
                    map, headers);
ResponseEntity<String> result = template.get().exchange(
                    contextPath.get() + path, HttpMethod.POST, requestEntity,
                    String.class);
>>>>>>> b494d6cea61253f648b912ce216862387070907c
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
### NODE
--------------------------------------------------------------------------------------------------------
npm install fs-extra
npm install google-closure-compiler
npm install preprocessor

npm run test
npm run test:watch
npm run test:release
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------
### VIM
--------------------------------------------------------------------------------------------------------
1. Insert mode (Where you can just type like normal text editor. Press i for insert mode)
2. Command mode (Where you give commands to the editor to get things done . Press ESC for command mode)

Most of them below are in command mode

    x - to delete the unwanted character
    u - to undo the last the command and U to undo the whole line
    CTRL-R to redo
    A - to append text at the end
    :wq - to save and exit
    :q! - to trash all changes
    dw - move the cursor to the beginning of the word to delete that word
    2w - to move the cursor two words forward.
    3e - to move the cursor to the end of the third word forward.
    0 (zero) to move to the start of the line.
    d2w - which deletes 2 words .. number can be changed for deleting the number of consecutive words like d3w
    dd to delete the line and 2dd to delete to line .number can be changed for deleting the number of consecutive words

The format for a change command is: operator [number] motion
-operator - is what to do, such as d for delete
- [number] - is an optional count to repeat the motion
- motion - moves over the text to operate on, such as w (word),
$ (to the end of line), etc.

    p - puts the previously deleted text after the cursor(Type dd to delete the line and store it in a Vim register. and p to put the line)

    r - to replace the letter e.g press re to replace the letter with e

    ce - to change until the end of a word (place the cursor on the u in lubw it will delete ubw )

    ce - deletes the word and places you in Insert mode

    G - to move you to the bottom of the file.

    gg - to move you to the start of the file.
    Type the number of the line you were on and then G

    % to find a matching ),], or }

    :s/old/new/g to substitute 'new' for 'old' where g is globally

    / backward search n to find the next occurrence and N to search in opposite direction

    ? forward search

    :! to run the shell commands like :!dir, :!ls

    :w - TEST (where TEST is the filename you chose.) . Save the file

    v - starts visual mode for selecting the lines and you can perform operation on that like d delete

    :r - Filename will insert the content into the current file

    R - to replace more than one character

    y - operator to copy text using v visual mode and p to paste it

    yw - (copy)yanks one word

    o - opens a line below the cursor and start Insert mode.

    O - opens a line above the cursor.

    a - inserts text after the cursor.

    A - inserts text after the end of the line.

    e - command moves to the end of a word.

    y - operator yanks (copies) text, p puts (pastes) it.

    R - enters Replace mode until <ESC> is pressed.

    ctrl-w to jump from one window to another

type a command :e and press ctrl+D to list all the command name starts with :e and press tab to complete the command
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