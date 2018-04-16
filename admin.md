## Administration

* Delete files older than x number of days
```bash
find /path/to/files* -mtime +x -exec rm {} \;
```

* Zip and date a file.
```bash
cat /path/to/file | gzip > /new/path/to/file-$(date +"%Y%m%d-%H%M").gz
```

* Remove comments and such from a file for easier viewing
```bash
grep -Pv ^'(\s+|#|$)'
```

* Change permissions for all files
```bash
find . -type f -exec chmod <permissions here> {} ;
```

* Change permissions for all directories
```bash
find . -type d -exec chmod <permissions here> {} ;
```

* Find files older than 180 days at the given location and print them to screen.
```bash
find /var/log/apache2 -mindepth 1 -mtime +180 -depth -print
```

* Find files older than 180 days and delete.
```bash
find /var/log/apache2 -mindepth 1 -mtime +180 -delete
```

* List crontab for all users
```bash
for i in $(getent passwd | cut -d: -f1 ); do printf "User:$i\n"; crontab -l -u $i; printf "\n"; done; for i in $(find /etc/cron* -type f); do printf "\n-----------\n File:$i \n-----------\n"; cat $i; done
```

* Memory usage on a server
```bash
free -m | awk 'NR==1 {printf ("%18s %10s %10s\n",$1,$2,$3)}; NR==2 {printf ("%s %13s", $1, $2)}; NR==3 {printf ("%11s %10s\n", $3, $4)}; NR==4 {print}' | awk 'NR==1 {printf ("%s %10s\n", $0, "% used")}; NR!=1 {printf ("%s %10.4s\n", $0, $3/$2*100)}'
```

* Determine processes contributing to load average.
```bash
ps arux
```


### Commands
#### grep

* Print for first column numbers, useful for device numbers.
```bash
grep -Po '^\s*|d+' file
```

#### netcat

* Test connection to a port; syntax is command flags host port
```bash
# nc -vz 192.168.0.1 9543
```

#### tar

* List all files in archive.tar verbosely.
```bash
tar -tvf archive.tar
```

* List all file files in archive.tar.gz verbosely. The `z` option allows you to do this on a gzipped archive
```bash
tar -tzvf archive.tar.gz
```

* Create archive.tar from files foo and bar.
```bash
tar -cf archive.tar foo bar
```

* Create archive.tar.gz from files foo and bar and gzip the archive; verbosely lists files archived.
```bash
tar -cvfz archive.tar foo bar
```

#### screen

Press `CTRL+A` then `D` to exit a screen.

* List out current screens.
```bash
screen ls
```

* Give a custom name to a screen session.
```bash
screen -s <namescreen>
```

### Databases
#### MySQL
##### phpmyadmin

For adding access to phpMyAdmin edit `/etc/httpd/conf.d/phpMyAdmin.conf`. Under Apache 2.2 add an `allow` entry for the IP in question. The change requires a `service httpd graceful` to complete.

* Increase upload limit specific to phpmyadmin

First, what was done was to edit the /etc/phpMyAdmin/apache.conf and the following line under the <Directory /usr/share/phpMyAdmin/>:

   AllowOverride All

This allows for the .htaccess file that we are creating to be read. Then we created the file /usr/share/phpMyAdmin/.htaccess as /etc/phpMyAdmin/apache.conf calls to that directory. Here is the parameters added to that file:

php_value post_max_size 3000M
php_value upload_max_filesize 3000M

I then verified that were active by creating a /usr/share/phpMyAdmin/phpinfo.php. In that page I verified that the Local Values for these two parameters are the same as the .htaccess values where as the Master Values are the same as the /etc/php.ini values.

### Disk

* Check if a block device is going to fsck
```bash
tune2fs -l /path/to/block/device | egrep -i 'Max|Check'
```

* Prefab for fsck.
```bash
Rebooting server [servernamehere]
   This server has been up for 600+ days. The system will run a filesystem check on every reboot after 180 days.  The filesystem check, checks for consistency and there is no way to tell how long it will take.   On a healthy filesystem it takes less than 30 seconds.  On an unhealthy system it can take hours.   I see no reason so suspect any problems with the filesystem but if there is, there is a risk of that extending the downtime.
```

* See what is using most of the space on / (Size Check)
```bash
df -h / && du -h / | grep -P ^[0-9.]*G | sort -nr | head -40
```

* Sets reserve space to 1% (Temporary measure can be used on hard drives flagging as full. Default is 5%)
```bash
tune2fs -m 1 /dev/sda5
```

### Mail

Outgoing Mail
Regular SMTP - 25
Secure SMTP - 465

Incoming Mail
Regular IMAP - 143
Secure IMAP - 993
Regular POP3 - 110
Secure POP3 - 995

#### Postfix

* List/print the current mail queue.
```
postqueue -p
mailq
```

* Flush the mail queue.
```
postqueue -f
```

* Schedule immediate delivery of all mail that is queued for the named as domain.com.
```
postqueue -s domain.com
```

* Delete all mail queue.
```
postsuper -d ALL
```

* Delete a particular message.
```
postsuper -d $messageid
```

* Requeue the mail or resend particular mail.
```
postfix -r $messageid
```

* Find the mail version.
```
postconf -d mail_version
```

### Networking

* Find the internal and their corresponding external IPs on a server.
```bash
echo; column -t <<< "$(echo "IFACE INTERNAL EXTERNAL"; while read line; do iface=$(cut -d' ' -f1 <<< $line); ip=$(cut -d' ' -f2 <<< $line); extip=$(curl -sm1 --interface $iface canhazip.com); echo "$iface $ip $extip"; done <<< "$(ip -4 a | awk '/^( )+inet/ {print $NF, $2}')")"; echo
```

* IP Adjustment

Using `ip` command add an IP.

If you prefer to use the ip command instead of ifconfig
```bash
ip address add [ip]/[mask-digits] dev [nic]

Example:
ip address add 192.168.100.37/24 dev eth0
[Sauce](https://www.garron.me/en/linux/add-secondary-ip-linux.html)
```

* Adjust IP address for interface on RHEL >7.1
```bash
nmcli con mod em1 ipv4.addresses 172.24.48.44/22
nmcli con mod em1 ipv4.gateway 172.24.48.1
nmcli con mod em1 ipv4.method manual
nmcli con up em1
```

#### bonding

* NIC bonding
Bonding tutorial under Alan hicks home
Active-backup is the only supported one at rackspace
It requires that both interfaces are hooked up to a switch and that they are  both in the same vlan
Rs recommend to use bonding.py script which uses python
Puts every interface into promiscuous mode and then sends out a generous arp request to see which nics are in the same vlan
Alan's wiki contains walk through for nmcli
Con-name is basically profile name in nmcli  try to make them the same as what's in network manager to make it easier
Sysfs mode is not permanent

NIC bonding requires two NIC cards to work right. If you bond two ports on the same NIC it is still a single point of failure.

#### DNS

C-name records need to be unique across all record types

#### firewalld
```bash
firewall-cmd --state
firewall-cmd --get-default-zone
firewall-cmd --get-active-zones
firewall-cmd --zone=public --add-interface=eth0
firewall-cmd --reload
firewall-cmd --zone=public --list-ports
firewall-cmd --zone=public --add-port=8983/tcp --permanent
firewall-cmd --zone=public --list-services (Whats Live)
firewall-cmd --get-services (Whats available)
firewall-cmd --add-service=http
firewall-cmd --permanent --add-service=mysql
firewall-cmd --reload
firewall-cmd --permanent --zone=public --add-source=192.168.10.0/24
firewall-cmd --permanent --zone=public --remove-source=192.168.3.9/24

firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=222.186.21.0/18 reject"

firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=69.30.213.202 reject"
firewall-cmd --zone=public --list-all

firewall-cmd --permanent --zone=public --add-rich-rule="rule family="ipv4" source address="1.2.3.4/32" port protocol="tcp" port="3306" accept"
firewall-cmd --permanent --zone=public --add-rich-rule="rule family="ipv4" source address="69.30.213.202/32" port protocol="tcp" port="3306" deny”


firewall-cmd --permanent --zone=trusted --change-interface=eth1
firewall-cmd --permanent --add-service=httpd --zone=trusted
```

#### iptables

Remove IP from IPtables by specifying jail and line number
iptables -D fail2ban-ssh-ddos 1

Display IP Tables rules by jail and line number
iptables -L -vn --line-numbers

block a range rather than a subnet
iptables -A INPUT -p tcp --destination-port 80 -m iprange --src-range 46.229.168.66-46.229.168.74 -m comment --comment "Ticket 161217-iad-0000355" -j DROP

### Packages
#### rpm

* Rebuild RPM database.
```bash
cd /var/lib/rpm
mkdir /home/rack/170622-01234
mv /var/lib/rpm/__db* /home/rack/170622-01234/
/usr/lib/rpm/rpmdb_verify Packages
echo $?
rpm -vv --rebuilddb
/usr/lib/rpm/rpmdb_verify Packages
```

#### yum

/etc/yum.repos.d/repolistedhere.repo file

[repo]
name = Name of Repo
baseurl = Location of repo (URL usually)
enabled = 1

enabled=value (where value is one of the following:)
	0 - Do not include this repository as a package source when performing updates and installs. This is an easy way of quickly turning repositories on and off, which is useful when you desire a single package from a repository that you do not want to enable for updates or installs.
	1 - Include this repository as a package source.

When excluding packages use one exclude statement and keep the packages on the same line space or comma separated.

Turning repositories on and off can also be performed by passing either the --enablerepo=repo_name or --disablerepo=repo_name option to yum, or through the Add/Remove Software window of the PackageKit utility.

### Security

* Generates a self-signed key and certificate pair with OpenSSL.
```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/apache-selfsigned.key -out /etc/ssl/certs/apache-selfsigned.crt
```

* Remove ssl passphrase from key.
```
openssl rsa -in key.pem -out newkey.pem
```

#### fail2ban

* Unban IP
```bash
fail2ban-client set $jail unbanip 1.2.3.4
example: fail2ban-client set sshd unbanip 67.11.48.220
```

* Unban an Ip from a jail.
```bash
fail2ban-client set sshd unbanip 67.11.48.220
```
* Show current status of jail where sshd is jail name.
```bash
fail2ban-client status sshd
```

On rhel 7 check ‘ipset list’ for banned ips RHEL7 uses ipset which is below iptables to quickly parse through IP lists unlike >6 which would read chains.

### Storage
#### Wisdom

With modern partitioning always use GPT and avoid MBR. This is do to the limit of size for a file system using MBR (4) and primary partitions (3 plus 1 extended).

#### fdisk
#### parted

* Partition a disk, set it as GPT, create 3 partitions for LVM.
```bash
parted /dev/sdb -s print
Error: /dev/sdb: unrecognised disk label
Model: VMware Virtual disk (scsi)
Disk /dev/sdb: 17.2GB
Sector size (logical/physical): 512B/512B
Partition Table: unknown
Disk Flags:

parted /dev/sdb -s mklabel gpt

parted /dev/sdb -s mkpart primary ext3 2 50%

parted /dev/sdb -s mkpart primary ext3 50% 80%

parted /dev/sdb -s mkpart primary ext3 80% 100%

parted /dev/sdb -s set 1 lvm on

parted /dev/sdb -s set 2 lvm on

parted /dev/sdb -s set 3 lvm on

parted /dev/sdb -s print
Model: VMware Virtual disk (scsi)
Disk /dev/sdb: 17.2GB
Sector size (logical/physical): 512B/512B
Partition Table: gpt
Disk Flags:
Number  Start   End     Size    File system  Name     Flags
 1      2097kB  8590MB  8588MB               primary  lvm
 2      8590MB  13.7GB  5154MB               primary  lvm
 3      13.7GB  17.2GB  3435MB               primary  lvm
```

#### LVM

Setup basic LVM partition.
```bash
# pvcreate pv01 /dev/svda1

# vgcreate vglocal01 /dev/svda1

# lvcreate -L 10G --name stuff vglocal01
```

##### Wisdom

Make sure you have removed mount points before removing LVM.

On a snapshot the size is reserved for changes to the file system while the snap shot is being taken.

lvcreate is used to create a snapshot

Shrink the filesystem a little under the size of the lv reduction then shrink the lv and then resize the filesystem to the new size of the reduced lv

### Users

* Reset user’s password and have it reset on first login.
```bash
echo "P^$$w0R>" | passwd user --stdin && chage -d 0 user

```

* Display users with bash shell
```bash
awk -F: '{if ($3 >= 500) {print $1 ":" $3 ":" $7} }' /etc/passwd | grep -i bash
```

* Display users without a bash shell
```bash
awk -F: '{if ($3 >= 500) {print $1 ":" $3 ":" $7} }' /etc/passwd | grep -v bash
```

* User deletion
```bash
egrep -i “FirstName|LastName” /etc/passwd chage --expiredate 0 $USER
usermod --lock --shell /bin/false $USER usermod --comment “User disabled per ticket BLAH” $USER
```

sftp

ORIGINAL VALUE:
  Subsystem sftp internal-sftp -u 0002

   The -u 0002 option at the end is not supported by the OpenSSH packages available to RHEL 5; it is only valid on RHEL 6 or later. I removed that option and restarted the SSH daemon to load the new configuration.

Configure CHROOT user https://one.rackspace.com/pages/viewpage.action?title=Configuring+a+Chrooted+SFTP-Only+User&spaceKey=Linux

* Bind SFTP user to path.
```bash
mount -o bind /path/to/destination /path/to/jailedusershomedir

/path/to/destination /path/to/jailedusershomedir none rw,bind,nobootwait 0 0
```

#### Vsftpd

Jail specific users with vsftpd
http://unix.stackexchange.com/questions/90472/jail-only-a-specific-user-with-vsftpd

### Web Servers

* Mimic a curl from localhost.
```bash
curl -IvLH 'Host:example.com’ http://localhost
```

#### Apache

yum install -y mod_ssl
mkdir /etc/httpd/ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/httpd/ssl/apache.key -out /etc/httpd/ssl/apache.crt<<EOF

US
TX San Antonio
deLag Enterprises
IT
delag.net
admin@delag.net
EOF

Remove apache server header? Install mod_security on EL 6.9

Before:
$ curl -IL chrisdlg.com
HTTP/1.1 200 OK
Date: Fri, 11 Aug 2017 00:06:10 GMT
Server: Apache/2.2.15 (CentOS) DAV/2 PHP/5.3.3 mod_ssl/2.2.15 OpenSSL/1.0.1e-fips
X-Powered-By: PHP/5.3.3
Link: <http://chrisdlg.com/wp-json/>; rel="https://api.w.org/"
Link: <http://wp.me/P90LLz-n>; rel=shortlink
Connection: close
Content-Type: text/html; charset=UTF-8

After:
$ curl -IL chrisdlg.com
HTTP/1.1 200 OK
Date: Fri, 11 Aug 2017 00:17:04 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
Set-Cookie: __cfduid=d30be725c55f32a75763ea5b282fe184b1502410624; expires=Sat, 11-Aug-18 00:17:04 GMT; path=/; domain=.chrisdlg.com; HttpOnly
X-Powered-By: PHP/5.3.3
Link: <http://chrisdlg.com/wp-json/>; rel="https://api.w.org/"
Link: <http://wp.me/P90LLz-n>; rel=shortlink
Server: cloudflare-nginx
CF-RAY: 38c7028010911fb2-DFW

Best practices is to list individual configs in the .d directory, this example pertains to things like apache where you would want to have your virtual hosts in the conf.d directory.

==========================port 80 vhost=========================================
<VirutalHost ip:port>
	DocumentRoot "/var/www/example.com/public_html/"
	ServerName example.com
	ServerAlias www.example.com
	ErrorLog logs/example.com-error_log
	Customlog logs/example.com-access_log common
</VirtualHost>
=============================================================================

Sort Virtual Hosts by alphabetical order.
# find /etc/httpd/ -name *.conf | column -s "/" -t | awk '{print $NF}' | sort | head


Redirect on httpd 2.2 (URI specfic)
RewriteRule ^/nyc/programs/policy.php$	http://www.example.com/nyc/what-we-do/policy-and-advocacy/ [L,R=301]

Redirect on httpd 2.2 (catch all)
RewriteRule ^/nyc/(.*)$    http://www.example.com/nyc/ [L,R=301]

For loop to test URI redirect:
# for i in `cat uris3.txt`; do echo $i; curl -I http://example.com$i; done


Redirect 301
---------------------------------------------------
<VirtualHost *:80>
    ServerName example.com
    Redirect permanent / https://www.example.com/
</VirtualHost>
---------------------------------------------------
Redirect 301 Apache 2.4
---------------------------------------------------
RewriteEngine on
RewriteCond %{HTTPS} !=on
RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [R,QSA]
---------------------------------------------------

grep '17/Dec/2016:01' /var/www/*/logs/access_log | awk '{print $1}' | sort -n | uniq -c | sort -nr | head -25
egrep -h 21/Dec/2016:1[7-9] *access.log | awk '{print $1}' | sort -n | uniq -c | sort -nr		<— sort apache logs by date/time and print top IPs

.htaccess HTTP to HTTPS
<IfModule mod_rewrite.c>
    RewriteEngine on
    RewriteCond %{HTTPS} !=on
    RewriteRule ^(.*)$ https://%{HTTP_HOST}/$1 [R,QSA]
</IfModule>

Apache Buddy
curl -sL https://raw.githubusercontent.com/richardforth/apache2buddy/master/apache2buddy.pl | perl

SSL Info All
echo | openssl s_client -connect site:443 2>/dev/null | openssl x509 -noout -text

Top IPs and Country
for i in `awk '{print $1}' /var/log/httpd/access_log | sort | uniq -c | sort -n | tail'`; do echo $i; whois $i | grep -i country | tail -1; done

Rewrite rule for http to https:

RewriteEngine On
    RewriteCond %{HTTPS} !=on
    RewriteRule ^/?(.*) https://%{SERVER_NAME}/$1 [R=301,L]
----------------------------------------------------------
Apache Redirect Addition (HTTP to HTTPS):
RewriteEngine On
# This will enable the Rewrite capabilities

RewriteCond %{HTTPS} !=on
# This checks to make sure the connection is not already HTTPS

RewriteRule ^/?(.*) https://%{SERVER_NAME}/$1 [R,L]
# This rule will redirect users from their original location, to the same location but using HTTPS.
# i.e.  http://www.example.com/foo/ to https://www.example.com/foo/
# The leading slash is made optional so that this will work either in httpd.conf
# or .htaccess context
------------------------------------
When seeing an apache conf file serving content on a non-standard port look to nginx as a possible front end for this to serve content to apache as a proxy on the backend.
------------------------------------
# To configure and get apachectl full status working:
# Enable this configuration block:
<Location /server-status>
    SetHandler server-status
    Order allow,deny
    Allow from localhost 127.0.0.1
</Location>
# Instal elinks
# Uncomment the Extended Status On
ExtendedStatus On
# Restart Apache upon completion
------------------------------------
To enable Apache fullstatus on Ubuntu make sure to run the following command and restart Apache:
a2enmod status
------------------------------------
apachectl fullstatus
install links to run the apachectl fullstatus command as apache is the application that is hammering the server
------------------------------------
Lines added to the ssl.conf file.

SSLHonorCipherOrder on
SSLProtocol ALL -SSLv2 -SSLv3
SSLCipherSuite <CIPHERS>
# Recommended SSL Cipher Suite for Securing Apache
# Pretty strong Cipher Suite to use.
SSLCipherSuite EECDH+AESGCM:EECDH+AES256:EECDH+AES128

# For additional security include this line in the vhost container:
Header always set Strict-Transport-Security "max-age=63072000; includeSubdomains;"


SSLEngine on
SSLCertificateFile /etc/pki/tls/certs/localhost.crt
SSLCACertificateFile /etc/pki/tls/certs/ca-bundle.crt
SSLCertificateKeyFile /etc/pki/tls/private/localhost.key


# In Nginx this is the cipher string.
ssl_cipher 'EECDH+AESGCM:EECDH+AES256:EECDH+AES128';

Cipher strings (This goes into the field called <CIPHERS>)
------------------------------------
HTTP Troubleshooting

1. pstree|grep httpd
2. grep maxclients apache config file
3. netstat (see what web server is being run)
4. Check for other people on box and idle time
5. apachectl fullstatus (apache status command)

Place to check Servermill (Post build automation process)
reports.servermill.rackspace.net

How can I test for HTTP TRACE on my web-server?
curl -v -X TRACE http://www.yourserver.com
——————————————————————————————————————————————————————

* Bad bot block with a .htaccess file.
```bash
SetEnvIfNoCase ^User-Agent$ (^$|MSIE.6|Baiduspider|Sosospider|EasouSpider|Sogou|Ahrefs|YandexBot|TurnitinBot|Indy.Library|BLEXBot|URLAppendBot|ZmEu|MJ12bot|80legs|blekko|PaperLiBot|MetaURI|UnwindFetchor|FlipboardProxy|hivaBot|MixrankBot|magpie|ZumBot|SISTRIX|CrawlDaddy|musobot|QuerySeeker|CSchecker|Spinn3r|Genieo|rogerbot|SemrushBot) bad_bot
<Limit GET HEAD POST>
	order allow,deny
	allow from all
	deny from env=bad_bot
</Limit>
```

* Block access to XMLRPC, but allow those that need it.
```bash
# https://wordpress.org/support/topic/jetpack-xmlrpcphp-help
<Files xmlrpc.php>
	Order deny,allow
	Deny from all
	# Loopback and private ranges
        Allow from ::1 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16
  # Additional IPs here
	Allow from 192.168.0.1/24 10.0.20.10/24
</Files>
```

* Measures to block out  SQL injection attacks
```bash
RewriteCond %{QUERY_STRING} ^.*(;|<|>|'|"|\)|%0A|%0D|%22|%27|%3C|%3E|%00).*(/\*|union|select|insert|cast|set|declare|drop|update|md5|benchmark).* [NC,OR]

# Prevent use of specified methods in HTTP Request
RewriteCond %{REQUEST_METHOD} ^(HEAD|TRACE|DELETE|TRACK) [NC,OR]
# Block out use of illegal or unsafe characters in the HTTP Request
RewriteCond %{THE_REQUEST} ^.*(\\r|\\n|%0A|%0D).* [NC,OR]
# Block out use of illegal or unsafe characters in the Referer Variable of the HTTP Request
RewriteCond %{HTTP_REFERER} ^(.*)(<|>|'|%0A|%0D|%27|%3C|%3E|%00).* [NC,OR]
# Block out use of illegal or unsafe characters in any cookie associated with the HTTP Request
RewriteCond %{HTTP_COOKIE} ^.*(<|>|'|%0A|%0D|%27|%3C|%3E|%00).* [NC,OR]
# Block out use of illegal characters in URI or use of malformed URI
RewriteCond %{REQUEST_URI} ^/(,|;|:|<|>|">|"<|/|\\\.\.\\).{0,9999}.* [NC,OR]
# Block out  use of empty User Agent Strings

# NOTE - disable this rule if your site is integrated with Payment Gateways such as PayPal
# DISABLED RewriteCond %{HTTP_USER_AGENT} ^$ [OR]

# Block out  use of illegal or unsafe characters in the User Agent variable
RewriteCond %{HTTP_USER_AGENT} ^.*(<|>|'|%0A|%0D|%27|%3C|%3E|%00).* [NC,OR]
# Measures to block out  SQL injection attacks
RewriteCond %{QUERY_STRING} ^.*(;|<|>|'|"|\)|%0A|%0D|%22|%27|%3C|%3E|%00).*(/\*|union|select|insert|cast|set|declare|drop|update|md5|benchmark).* [NC,OR]
# Block out  reference to localhost/loopback/127.0.0.1 in the Query String
RewriteCond %{QUERY_STRING} ^.*(localhost|loopback|127\.0\.0\.1).* [NC,OR]
# Block out  use of illegal or unsafe characters in the Query String variable
RewriteCond %{QUERY_STRING} ^.*(<|>|'|%0A|%0D|%27|%3C|%3E|%00).* [NC]
```

* Block MySQL injections, RFI, base64, etc.
```bash
RewriteCond %{QUERY_STRING} [a-zA-Z0-9_]=http:// [OR]
RewriteCond %{QUERY_STRING} [a-zA-Z0-9_]=(\.\.//?)+ [OR]
RewriteCond %{QUERY_STRING} [a-zA-Z0-9_]=/([a-z0-9_.]//?)+ [NC,OR]
RewriteCond %{QUERY_STRING} \=PHP[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12} [NC,OR]
RewriteCond %{QUERY_STRING} (\.\./|\.\.) [OR]
RewriteCond %{QUERY_STRING} ftp\: [NC,OR]
RewriteCond %{QUERY_STRING} http\: [NC,OR]
RewriteCond %{QUERY_STRING} https\: [NC,OR]
RewriteCond %{QUERY_STRING} \=\|w\| [NC,OR]
RewriteCond %{QUERY_STRING} ^(.*)/self/(.*)$ [NC,OR]
RewriteCond %{QUERY_STRING} ^(.*)cPath=http://(.*)$ [NC,OR]
RewriteCond %{QUERY_STRING} (\<|%3C).*script.*(\>|%3E) [NC,OR]
RewriteCond %{QUERY_STRING} (<|%3C)([^s]*s)+cript.*(>|%3E) [NC,OR]
RewriteCond %{QUERY_STRING} (\<|%3C).*iframe.*(\>|%3E) [NC,OR]
RewriteCond %{QUERY_STRING} (<|%3C)([^i]*i)+frame.*(>|%3E) [NC,OR]
RewriteCond %{QUERY_STRING} base64_encode.*\(.*\) [NC,OR]
RewriteCond %{QUERY_STRING} base64_(en|de)code[^(]*\([^)]*\) [NC,OR]
RewriteCond %{QUERY_STRING} GLOBALS(=|\[|\%[0-9A-Z]{0,2}) [OR]
RewriteCond %{QUERY_STRING} _REQUEST(=|\[|\%[0-9A-Z]{0,2}) [OR]
RewriteCond %{QUERY_STRING} ^.*(\[|\]|\(|\)|<|>).* [NC,OR]
RewriteCond %{QUERY_STRING} (NULL|OUTFILE|LOAD_FILE) [OR]
RewriteCond %{QUERY_STRING} (\./|\../|\.../)+(motd|etc|bin) [NC,OR]
RewriteCond %{QUERY_STRING} (localhost|loopback|127\.0\.0\.1) [NC,OR]
RewriteCond %{QUERY_STRING} (<|>|'|%0A|%0D|%27|%3C|%3E|%00) [NC,OR]
RewriteCond %{QUERY_STRING} concat[^\(]*\( [NC,OR]
RewriteCond %{QUERY_STRING} union([^s]*s)+elect [NC,OR]
RewriteCond %{QUERY_STRING} union([^a]*a)+ll([^s]*s)+elect [NC,OR]
RewriteCond %{QUERY_STRING} (;|<|>|'|"|\)|%0A|%0D|%22|%27|%3C|%3E|%00).*(/\*|union|select|insert|drop|delete|update|cast|create|char|convert|alter|declare|order|script|set|md5|benchmark|encode) [NC,OR]
RewriteCond %{QUERY_STRING} (sp_executesql) [NC]
RewriteRule ^(.*)$ - [F,L]
```

#### bots

There are a couple of ways to block a bot from your site.
The suggested way is with a robots.txt file. This tells bots listed how they can search your site, how often and what page. You can find information on writing a robots.txt file here:
http://www.robotstxt.org/

If we find the bot is not respecting the robots.txt, we can add their IP to your firewall blacklist. I looked over your logs and wasn't able to find anything that matches "maptrackers" and so I'm not able to say what their IP may be at the moment.

Finally, you can attempt to create a redirect rule that blocks by user agent. This isn't supported by rackspace and there are ways to get around it, but if you'd like to look into it with your developers, you can find more information, here:

http://webmasters.stackexchange.com/questions/50050/how-do-i-block-a-user-agent-from-apache

* Crawl delay for bot.
```bash
User-agent: *
Crawl-delay: 10
```

#### nginx

Logs - /var/log/nginx/<site>_access.log
global config = /etc/nginx/nginx.conf
default server root = /usr/share/nginx/html
location specified in = /etc/nginx/conf.d/default.conf

server blocks aka Virtual Hosts
new server blocks can be placed in /etc/nginx/conf.d and end in the .conf extension, same process as apache

https://one.rackspace.com/display/CSMO/Nginx
http://kbeezie.com/nginx-configuration-examples/

HTTP to HTTPS redirect (static files are processed directly by nginx)
if ($ssl_protocol = "") {
 rewrite ^/(.*) https://$server_name/$1 permanent;
}

redirect 301 permenanet
server {
   listen       80;
   server_name  example.com;
   return       301 https://www.example.com$request_uri;
}

 SSL  with nginx has the CRT and CA in the same file but the CRT is on top so the PK can decrypt it

List vhost similar to httpd -S
nginx -T | grep -P '(\.conf|server_name)'

Alternative to above that is distro agnostic
curl -s nginxctl.rax.io | python - -S

#### php-fpm

php-fpm hitting max children? adjust `/etc/varnish/default.vcl` and `/etc/nginx/nginx.conf`

#### php

* Show php-fpm average memory usage (Calculate this with maxchildren to get total RAM utilization)
```bash
ps -o pid= -C php-fpm \
  | xargs pmap -d \
  | awk '/private/ {c+=1; sum+=$4} END {printf "Count: %i, Average: %.2f, Total: %.2f\n", c, sum/c/1024, sum/1024}'
```

## Troubleshooting
### Caching

* Clear Redis Cache where there are seperate instances on ports 6380, 6381, and 6382.
```bash
# telnet localhost 6380
flushall
quit

# telnet localhost 6381
flushall
quit

# telnet localhost 6382
flushall
quit
```

* Clear Varnish cache
```bash
varnishadm "ban req.url ~ \"http://example.com/$\""
```

* Restart Varnish.
```bash
service httpd stop; service varnish restart; service httpd start
```

* Varnish utility that prints like the apache log
```bash
varnishncsa
```

* Dry run for Varnish.
```bash
varnishd -C -f /etc/varnish/default.vcl
```

### Databases
#### mongo

Add a mongo DB user
```bash
mongo
> use admin
switched to db admin
> db.createUser({user: “user”,pwd: "PBz4b421",roles: [ "readWriteAnyDatabase"]})
Successfully added user: { "user" : “user”, "roles" : [ "readWriteAnyDatabase" ] }
```

#### MySQL
> If MySQL won't start check:
See if something else is bound to port 3306
Make sure there is sufficient free space (df -h)
Make sure there is sufficient free inodes (df -hi)
Make sure there is enough RAM (free -m)
The log file (/var/log/mysql.log)

* MySQL tuner
```bash
curl -sL https://raw.githubusercontent.com/major/MySQLTuner-perl/master/mysqltuner.pl | perl
```

* Enter mysql_safe mode for Percona MySQL

```bash
mysqld --user=mysql --skip-grant-tables
```

* Monitor MySQL statistics.
```bash
while true; do mysqladmin stat; sleep 3; done
```

* Show current data directory for MySQL
```bash
SHOW VARIABLES WHERE Variable_Name LIKE "%dir"
```

* Find table size and engine
```bash
SELECT table_name, round(((data_length + index_length) / 1024 / 1024), 2) `Size in MB`, engine FROM information_schema.TABLES WHERE table_schema="db” AND engine="MyISAM" ORDER BY (data_length + index_length) DESC;
```

* Forcing a mysqldump from a second running instance by specifying the socket
```bash
mysqldump --force --socket=/mnt/local/database/recovery_sandbox/data/mysql.sock database | gzip -c -9 > database.sql.gz
```

* Databases by size.
```bash
SELECT table_schema "database", sum(data_length + index_length)/1024/1024 "size in MB" FROM information_schema.TABLES GROUP BY table_schema;
```

* What engine is the table running.

```bash
mysql -e "USE dbhere; SHOW TABLE STATUS WHERE Name = ‘tablenamehere’\G”

or

mysql -e "SHOW TABLE STATUS FROM db LIKE ‘table’;”
```

* How was a table made?
```bash
mysql -e "SHOW CREATE TABLE db.table\G”
```

* List columns from a table.
```bash
mysql -e "SHOW CREATE TABLE db.table\G”
```

* Check a database's integrity
```bash
mysqlcheck <database name>
```

### Networking

iptraf

Current connections
netstat -antp | awk '$4 ~ /:80$/ {c++;print $5 | "sed 's/::ffff://' | sed 's/:.*$//'| sort | uniq -c | sort -n | tail -n 10"} END {print c}'

Ports in use
netstat -pntl | awk '{print $4}' | awk -F ":" '{print $2}' | sort | uniq | sort -n

#### tcpdump

* Don't translate hostnames, ports, etc...
```bash
tcpdump -n
```

* Add verbosity to tcpdump; tcpdump has three verbosity levels, you can add more verbosity by adding additional v's to the command line flags.
```bash
tcpdump -v
```

* Specify an interface to trace (dump) from. By default when you run tcpdump without specifying an interface it will choose the lowest numbered interface, usually this is eth0 however that is not guaranteed for all systems.
```bash
tcpdump -i eth0
```

If you want it from all interfaces this can be accomplished with `any`.
```bash
tcpdump -i any
```

* Save the output of tcpdump to a file. By default the data is buffered and will not usually be written to the file until you CTRL+C out of the running tcpdump command.
```bash
tcpdump -w /var/tmp/output.pcap
```

### Security

> Compromise?
1. Check for running processes
2. Check for php,java,python processes (who is running php)
3. Check/change your passwords
4. Check for open permissions

* Failed IPs Logins
```bash
grep -P 'Failed password for' /var/log/secure | sed 's/invalid user/ /g' | awk '{print $11}' | sort -n | uniq -c | sort -nr | head -30
grep -P 'Failed password for' /var/log/auth.log | sed 's/invalid user/ /g' | awk '{print $11}' | sort -n | uniq -c | sort -nr | head -30
grep -P 'Failed password for root' /var/log/secure | awk '{print $11}'| sort | uniq -c |sort -nr|head -30
```

* Failed User Logins
```bash
grep -P 'Failed password for' /var/log/secure | sed 's/invalid user/ /g' | awk '{print $9}' | sort -n | uniq -c | sort -nr | head
```

* Looking for FTP attempts
```bash
grep -P 'vsftpd' /var/log/message | awk '{print $13}' | sort -n | uniq -c | sort -nr | head
```

* Strip out blank lines and commented lines from a config file.
```bash
grep -Pv '^($|#)' <file name>
```

* In a parent directory find all subdirectories set to permissions of 777
```bash
find . -type d -perm 777 | wc -l
```

* In a parent directory find all subdirectories owned by the user $user.
```bash
find . -type d -user $user | wc -l
```

### Web Server

* Search access logs for IPs attempting to access known login or exploits.
```bash
grep POST /var/log/httpd/*access*log | egrep 'admin|login|xmlrpc' | awk '{print $1}' | sort | uniq -c | sort -rn | head -20
```

* Search logs for hits from non-US ips; replace d variable with date to search.
```bash
d='00/May/2017';while read i;do a=`curl -sL http://ipinfo.io/$i/country` ; if [ $a = "US" ];then exit; else b=`grep $i /var/log/httpd/*access*log | wc -l`;echo $i " hit " $b " times, from country "$a;fi 2>/dev/null & done <<< "`grep $d /var/log/httpd/*access*log |grep -oP '(\d{1,3}\.){3}\d{1,3}'|sort | uniq -c | sort -n|awk '$1 > 100 {print $2}'`" | tee
```

* Test as user agent
```bash
$ curl -A "Semrushbot" -IL http://example.com/
HTTP/1.1 403 Forbidden
Date: Thu, 25 May 2017 15:05:32 GMT
Server: Apache/2.2.15 (CentOS)
Accept-Ranges: bytes
Content-Length: 4961
Connection: close
Content-Type: text/html; charset=UTF-8
```

* Print top Bots/Crawlers from web logs.
```bash
Simplistic

egrep date /path/to/access_log | egrep -i "crawler|bot" | awk '{print $1 ":" $14}' | sort | uniq -c | sort -nr | head -15

Extended

grep <date> /var/log/httpd/*access*log | awk '{ print $14 }' | egrep -i "googlebot|yahoo|slurp|bing|yandex|baidu|radar|easou|mj12|semrush|ccbot|ahrefsbot|spbot|dotbot|pcore|blexbot|owlinbot|spinn3r" | cut -d/ -f1 | sort | uniq -c | sort -nr
```

* Find segmentation faults by day from apache error logs (replace Jun w/ month)
```bash
zgrep -i "Segmentation" /var/log/httpd/error_log-* /var/log/httpd/error_log |  grep -oP "\[.*Jun .. " | uniq -c
```

* Show php-fpm average memory usage (Calculate this with maxchildren to get total RAM utilization)
```bash
ps -o pid= -C php-fpm \
  | xargs pmap -d \
  | awk '/private/ {c+=1; sum+=$4} END {printf "Count: %i, Average: %.2f, Total: %.2f\n", c, sum/c/1024, sum/1024}'
```

* Established connections to web server.
```bash
netstat -ntulpa | grep :80 | grep -i established | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -n | wc -l
```

* Redirect www to non-www on apache 2.2
```bash
RewriteCond %{HTTP_HOST} ^www.example.com [NC]
RewriteRule ^(.*)$ http://example.com/$1 [L,R=301]
```
