![sql](https://cdn-images-1.medium.com/max/1140/1*41yYmwpxok33xGWGRcDlpg.jpeg)
## General Knowledge
### Good to Know
MariaDB is usually interchangeable with MySQL.
PerconaDB is similar to MySQL 5.6.

### Upgrade path
MySQL Upgrades in the following versions.
5.0 > 5.1 > 5.5 > 5.6 +

### Why use Databases?
* Use databases for speed and to store and organize information.
* When compared to a flat file reading and searching on databases is much faster.

Storage engines are per table not per database.
Relational databases (RDBM) uses rows and columns.

### Indexes
You only want to index the most common queries or the ones that are taking longest to process. Indexing everything is essentially indexing nothing.

### Data Files
* .FRM - schema of the tables in that database
* .MYD - MyISAM data file for that database
* .MYI - MyISAM index file for a table
* ibdata* - InnoDB data file (Cannot be shrunk)
* ib_logfile - the InnoDB Redo Logs. They should never be erased or resized until a full normal shutdown of mysqld has taken place.

[InnoDB Info](https://dba.stackexchange.com/questions/27083/what-exactly-are-iblog-files-in-mysql)

### Datadir?
The datadir is where MySQL and all of its data lives. This is usually /var/lib/mysql unless the main configuration file has been changed.

### Permissions
* What is the difference between connecting to mysql at localhost and at IP address?

  localhost connects to the socket and IP address connects to a port
* When creating users you can use a GRANT statement and skip using CREATE statements.

### MyISAM vs InnoDB Comparison
#### MyISAM
* Good if your database are read and not write heavy.
* Locks the entire table when writing or backing up.
* Can repair a table without bringing down the database 'MyISAMChk'.
* Default search engine for MySQL 5.0, 5.1, and 5.5?

#### InnoDB
* Does not like to be backed up while running.
* Invented row level locking.
* Can add rows without locking the entire database. It is just that single row being affected that is locked.
* Can run into disk i/o issues for large tables.
* Can't be shrunk (ibdata1).
* Default search engine of MySQL 5.6+

## Administration
### Automate MySQL logins from BASH shell
1. vim /root/.my.cnf
2. Here is the template for /root/.my.cnf
	[client]
	user=root
	password='passwordforroothere'
3. This can be put into the document root for any BaSH user with the credentials for any MySQL user. Can be useful for finding lost passwords.

### 3 Ways of importing databases
1. Method 1 : Directly into database via command line.
```
# mysql -u webuser -p database1 < database1.sql
```

2. Method 2 : Uncompress and import a database file.
```
As root user
# gzip -dc /home/user/database1.sql.gz | mysql database1
As a specific user
# gzip -dc /home/user/database1.sql.gz | mysql -u webuser -p database1
```

3. Method 3 : During login pulling db from current directory.
```
mysql -u webuser -p database1 \. database.sql
```

### Creating a backup (AKA copies) of a database.
The primary method with MySQL is via mysqldump
```
# mysqldump database1 < databasefileonserver.sql
```

##### mysqldump options
Dump all databases
* -A --all-databases
???? <-- Look into
* --opt
  mysql only
Include master data in sql dump. Used for replication.
* --master-data
???? <-- Look into
* --single-transaction

Dump a database
```
# mysqldump -u webuser -p database1
```

Dump a database to a specific file.
```
# mysqldump -u webuser -p database1 > database1.sql
```

Dump a database to a specific file and compress it (Use the --fast flag after gzip for a quicker compression that isn't as small in size).
```
# mysqldump -u webuser -p database1 | gzip > database1.sql.gz
```

### Holland
<Inset holland info>

### MySQL Admin
```
# mysqladmin -r processlist
```

```
# mysqladmin proc -v
```

### mysql -e
These commands can be run from BASH shell and not in MySQL server.
* Allows user(s) to run mysql commands from bash.
```
# mysql -e
```

* Display MySQL processes or queries. The below idea of placing a normal SQL command in '' can be applied for mysql -e.
```
# mysql -e 'SHOW FULL PROCESSLIST;'
```

* Get slave replication information and pipe for necessary fields.
```
# mysql -e 'show slave status \G;' | egrep -i "(slave|sec)"
    Slave_IO_State: Waiting for master to send event
    Slave_IO_Running: Yes
    Slave_SQL_Running: Yes
    Seconds_Behind_Master: 0
```

### Users
Remember that the '%' symbol means wildcard in MySQL. In user creation it means that user@% can login from anywhere. Any IP, localhost, you name it. A more secure method is to use user@IP if you plan to login to MySQL remotely(IP being the user's IP). If you are logging in from the local machine you will want to use user@localhost.

You can use GRANT statements instead of CREATE to reduce your keystrokes.

Best practices are to flush privileges every time post user modification/creation, even when using GRANT statments.

* Create root type user with password.
```
> GRANT ALL PRIVILEGES ON *.* TO 'newuser'@'%' IDENTIFIED BY 'securepass' WITH GRANT OPTION; FLUSH PRIVILEGES;
```

* Create regular user with password.
```
> GRANT ALL PRIVILEGES ON *.* TO 'newuser'@'%' IDENTIFIED BY 'securepass'; FLUSH PRIVILEGES;
```

* Give SELECT, UPDATE, INSERT, and DELETE on a sample database to a user.
```
> GRANT SELECT,UPDATE,INSERT,DELETE ON sample.* TO sample@locahost IDENTIFIED BY 'passwordsample';
```

* LOOK into
```
> DESC user;
```

* Show grants or permissions for a user
```
> SHOW GRANTS FOR user@localhost;
```

* Show MySQL users ending in oot.
```
> SELECT user, host, password FROM mysql.user WHERE USER LIKE "%oot";
```

* Update a user's password.
```
> UPDATE user set Password=Password('test') WHERE USER='sample';
```

* Another example of updating user password.
```
> UPDATE user set Password='passwordfromtheearlierselect'WHERE USER='dbadmin';
```

### Variables
* Search for Max Connections
```
# mysql -e "SHOW VARIABLES LIKE '%conn%';"
```

* Show threads connected.
```
# mysql -e "SHOW STATUS LIKE '%thread%';"
```

```
SET GLOBAL VARIABLE max_connections=500;

SHOW VARIABLES LIKE '%log%'

SET GLOBAL slow_query_log='/tmp/slow.log';

SHOW STATUS LIKE '%inno%';

SHOW STATUS LIKE '%buff%';
```

### Slow Query logging
1. Check for slow informaiton from /etc/my.cnf.
```
# egrep -i slow /etc/my.cnf
```

2. Add the following to /etc/my.cnf to enable slow query log.
```
slow-query-log=1
slow-query-log-file=/var/lib/mysqllogs/slow-log
```

3. Check to see if its enabled.
```
# egrep -i 'log-slow-queries|long_query_time' /etc/my.cnf
```

### Steps to setup Master/Slave replication
#### Good to Know
Bin log(transaction log) is where all the queries are journaled on the master, the slave will pull the bin log into a relay log(slave side of the bin log) relay log is usually behind the bin log, The master wont write anything to the bin log until it is done writing the query. This can create the perception that the slave is behind the master. Data between the slave and master is sent in clear text and should use the private network to help with bandwidth and security. We need to export the master database to the slave. The reason for this is the slave will only begin to read the new queries from the point that replication is turned on.

1. Add the following to the /etc/my.cnf file of the master server.
```
#Replication
log-bin=1-mysql-bin
server-id=1 expire-logs-days=3
binlog-format=MIXED
```
Avoid using STATEMENT based bin logging when possible use ROW or MIXED instead.

2. Add the following to the /etc/my.cnf file of the slave server.
```
#Replication
server-id=2
relay-log=2-relay-log
expire-logs-days=3
```

3. Run the following on the Master server and replace variables where necessary.
```
> GRANT REPLICATION CLIENT, REPLICATION SLAVE ON *.* TO 'replicationusername'@'ipaddressofslave' IDENTIFIED BY 'replicationuserpassword'; FLUSH PRIVILEGES; SHOW MASTER STATUS;
```
Make note of the output of SHOW MASTER STATUS, you will need it next.

4. Run the following on the Slave server and replace variables where necessary.
```
> CHANGE MASTER TO
MASTER_LOG_FILE='1-mysql-bin.000001',
MASTER_LOG_POS= 338,
MASTER_HOST='ipaddressofmaster',
MASTER_USER='replicationusername', MASTER_PASSWORD='replicationuserpassword';
SHOW SLAVE STATUS \G
```

5. Get a full copy of the MySQL databases from the Master and upload them into the Slave before starting the Slave.
  * On Master run the following then send it to the Slave securely.
  ```
  # mysqldump -A --master-data=1 > dump.sql; scp root@slaveip:/root/ dump.sql
  ```
  * On Slave import the dump file. Then start the slave.
  ```
  # mysql < dump.sql
  ```

#### Upgrading MySQL Master/Slave to 5.5 from 5.1
1. Add the IUS repository to both servers for MySQL 5.5 packages.
2. Run the following on the slave.
```
# service mysqld stop
# yum shell
    install mysql55 mysql55-server mysql55-libs mysqlclient16
    remove mysql mysql-server mysql-libs
    transaction solve (MAKE SURE YOU DO NOT REMOVE DEPENDENCIES ONLY REPLACE PACKAGES!!!)
    transaction run
# service mysqld start
# mysql_upgrade
```
3. Run the same commands on the master.

## Commands
### Show

* Show all databases in the Mysql Data Dir.
```
> SHOW DATABASES;
```

* Show all tables in the selected database.
```
> SHOW TABLES;
```

* Show all the indexes in a selected table. (If there are none, you may want to create some)
```
> SHOW INDEXES;
```

* Show the current status of all tables in the selected database.
```
> SHOW TABLES STATUS;
```

* Show the syntax of the create table command for a given table.
```
> SHOW CREATE TABLE;
```

* Show the currently running processes in MySQL.
```
> SHOW PROCESSLIST;
```

* Same as above but do not truncate the processes list fields.
```
> SHOW FULL PROCESSLIST;
```

### Use
* Select the database you wish to work in where database is the name of the database.
```
> USE database;
```

### Describe
* Describe the fields of a given table in a table format. This will show what fields are being indexed.
```
> DESCRIBE table;
```

### Group By
* Just what it sounds like.
```
> GROUP BY;
```

## Troubleshooting
**Always, always document your changes as you make them to quickly recover in case of a disaster.**
* Config and permissions are the issue 90% of the time.
* Try narrowing down the problem area.
* Have you checked the logs? Have you checked online MySQL documentation on the issue? dev.mysql.com/doc
* Change only one thing at a time! Use this with the first rule.
* Use 'top' and think of is it high or low in terms of resource usage. Low usually means web cluster or other issue such as a firewall rule changed?
* Have you checked disk usage? Go run 'df -h' or 'df -i' and look for utilization or block utilization.
* ULIMIT? Open file limit?
* STRACE? check to see what a process is doing!

### Recovering a lost root user password.
1. First check the following:
 * /root/.mysql_history
 * /root/.pgsql_history
 * history
 * /$USER/.mysql_history
2. Un-secure method to reset it, this does mean some brief downtime.

a. Stop MySQL and then start MySQL in safe mode and send it to the background.
```
  # service mysqld stop
  # mysqld_safe --skip-grant-tables --skip-networking&
```
b. Update the root user's password. DO NOT flush privileges here as it will cause issues since you ran --skip-grant-tables.
```
  # mysql -e 'USE mysql; UPDATE user set password=Password("recover") WHERE USER="root";'
```
c. Stop MySQL and then start it normally.
```
  # service mysqld stop; sleep 3; service mysqld start
```

3. Confirm you can login to MySQL now using the known root password. If you cannot check ps aux to see if the PID died correctly.

### High CPU issues
1. Run the following.
```
# mysql -e "SHOW FULL PROCESSLIST;"
```
You are looking for lots of queries in a running state. Quereies that are locked or sleep will not cause a high load. A 1,000 sleeping queries will not cause the load to increase. Running, sorting, and creatig queries will cause the load to increase. Also remember to check 'top'.

##### RANDOM THAT NEEDS TO GO above
Why use databases?
    Use databases for speed
    Vs reading and searching a flat file, databases are much faster
    There are levels of speed when it comes to memory
    Spinning disks are fastest read when the data is sequencial.
        So when you are creating the table, you will declare the length of the data
            INT(32), VARCHAR(65)...

Indexes
          Easy to create
                    "alter table X index ID
                    These are tables of pointers that pass to memory
                    An index will always be faster than a full tables scan
    A full table scan is only slightly faster than a plain text search

Definitions
    Database - a collection of tables
    Row - row
    Column - column or field
    Storage engine - Format/Strategy of storing table data on disk

Table Investigation
  Indexes - Basic concept of what they are and how to check if any exsist
  Primary Keys -

  Can you reset the password with out stoping mysqld?
  Yes actually
      since the mysql tables is MyISam table and it is not written to often, you can copy the user.FRM, user.MYD, user.MYI to another server with mysql
      Load up the second server with the original user.* DB files and start mysql


## Tuning 
Be wary of over allocating resources.
Key buffer size is the most important tuning option for MyISAM.
Open file limit is not tunable in /etc/my.cnf it is an OS issue located in /etc/security/limits.conf
Tuning-primer.sh and mysqltuner.pl are essentially the same but primer is more verbose.
	Read the link on the tuner script for tuner cache


##  Administration
If you want to work with the datadir directly MySQL service must be stopped or off.
Full table scans are bad, try to avoid them.
Sub-queries are bad because they create temporary tables.
	Apache is a forked process ps auxf will shows forks (thanks to the f switch) MySQL is a threaded model and is not forked.
Show indexes in <table>;
Show create table titles; <— look for primary key to find what is being indexed
Generally whenever something is joined to a field if that field is being indexed it will make it much faster.
If you do not see indexes just recommend to customers to do so but we do not know what to index.
When creating an index the table will be locked.
For databases you generally want to go RAID10
	Databases are for fast disk access, use a RAID that does the same ^
	Put the datadir on a separate volume so it doesn’t share the I/O pipe with the OS
	If you can tell MySQL not to put its log files with the datadir you are freeing up even more of the pipe
log_bin = variable for bin logging
Bin logs = writes
If you are bin logging you can run mysql -e “show master status”; to get the name of the log file then run a locate on the log file, if it doesn’t show don’t forget to run updatedb

```
# mysqlbinlog /path/to/bin/log will output it in human readable format
```
Create new bin log
```
mysql> flush logs;
```
Grep for expire from the global variables to find out how long the logs are being kept
The general log is ALL the queries.
3 things to set with slow log
Where is it?
Log timeout
What file am I using
Slow queries not using indexes

Mysql variables change from version to version, google if confused

Use the below for password reset
```
Select host, user, password from user where user = ‘root’
```
## Troubleshooting
If you see a field called “ID” it is most likely the index.
Indexes are useful because they store disk locations of information and can improve the speed of searches. Indexes can be sorted.
Locking issues are a giant red flag to move to InnoDB from MyISAM
Mysql -e “show global variables” | grep log <— show all logs
Data Corruption
If you want to run repairs on InnoDB stuff just start mysql
There is a variable for forcing InnoDB crash recovery.
innodb_force_recovery = 0 (0 is default and means its off, 1, 2, or 3 is okay, anything higher than 3 can permanently corrupt stuff)
Innochecksum will let you know if there is corruption on data (cannot be run on active mysql, mysql needs to be stopped)
```
mysql> check table <tables>; will check an active table
mysql> repair table <table>; will attempt repairs (MyISAM)
```
Myisamcheck <—bash
Myisamcheck -c will check for errors

## Backups with Holland
Look for the compression ratio to get an idea of how much disk space holland needs to complete the backup.
A common limit is .3
Exclude-invalid-views should be set to yes
/var/spool/holland is default for holland backups /etc/holland/holland.conf is where you can change this on the line backup_directory

Don’t have holland create a lvm backup to the same place that your datadir is

Lock-tables = master position

Look at the linux brown bag one wiki for pros and cons

Upgrade only one major version at a time
This is due to changes in each version and backwards compatibility, 5.0 to 5.1 to 5.5 to 5.6, etc…
If you are unsure of the compatibility between the versions escalate.
Back porting is taking an older version and applying the security fix from a newer version
	2 reasons to update software: security flaws or add new features
yum replace MySQL-server --replace-with=mysql51-server <— 5.0 to 5.1 upgrade
Steps to upgrade
	Stop MySQL
	Upgrade the packages (REMEBER ONE MAJOR VERSION AT A TIME)
	my.cnf syntax (think dbsake)
	Start MySQL
	mysql_upgrade <— for the SCHEMA
Replication is not a guarantee that the two servers have the same content.
	Really all the master does is bin log. The magic happens in the slave.
Slave IO thread <— network thread
Slave SQL thread <— talks to local sql instance

Until_Condition: None
Until_Log_File:
Until_Log_Pos: 0
The above is for replication and this is used when you only want to replicate to a certain point as defined in the start slave command. If you tell replication to work until a certain point you will see those values here.

Common issues for the slave is tuning and forgetting to tune the slave.

make sure to set all 5 variables on a CHANGE MASTER statement

3 options for binlog_format
In general use Mixed
On the slave use STATEMENT based bin logging since nothing is reading it but it is useful for the customer

Don’t forget on ORDER BY statements they are random by default, you need to specify some logic.

Replicate-ignore-db can be a bad thing
Use the table based version instead

Triple MMM configs are deprecated
	They are usually in passive or manual mode

Take the following as the bare minimum permissions (Read USER)
GRANT SELECT, RELOAD, SUPER, LOCK TABLES, REPLICATION CLIENT, SHOW VIEW, TRIGGER ON *.* TO 'rackspace_backup'@'localhost' IDENTIFIED BY 'XXXXXXXXXXXXXXXXXX';
Mysqldump -A —master-data=2 > dbs.sql

Be wary of when restarting a mysql instance that you are configuring as a slave that when you run service mysqld restart it will attempt to start the slave
