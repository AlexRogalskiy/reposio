#### NGINX
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

#### HTTPD
sudo service httpd start
​sudo service httpd stop
​sudo service httpd restart