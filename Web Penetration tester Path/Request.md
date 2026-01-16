## Web Penetration Testing FundamentalsThis module covers the core protocols and tools necessary for interacting with web applications, focusing on the HyperText Transfer Protocol (HTTP), its secure counterpart (HTTPS), and the versatile command-line tool `curl`.

### **1. Web Communication Basics**

| Concept | Description |
| --- | --- |
| **Web Request** | The process where a client (like a browser or `curl`) sends a message to a server to request a resource. |
| **HTTP** | **HyperText Transfer Protocol**. The foundation of data communication for the World Wide Web. Typically operates on **port 80** (unencrypted). |
| **HTTPS** | **Hypertext Transfer Protocol Secure**. The secure version of HTTP, using **TLS/SSL** for encryption. Typically operates on **port 443** (encrypted). |
| **DNS** | **Domain Name System**. Translates human-readable domain names (e.g., `inlanefreight.com`) into machine-readable IP addresses. |

---

### 2. Using `curl` for Web Interaction`curl` (Client URL) is a command-line tool for transferring data with URLs. It is essential for web pen-testing as it allows for precise, programmatic interaction with web servers.

#### **Basic Interaction & Downloading**

| Action | `curl` Command | Description |
| --- | --- | --- |
| **Simple Request** | `curl inlanefreight.com` | Sends a basic GET request and outputs the HTML response body to the terminal. |
| **Download & Save** | `curl -O inlanefreight.com/index.html` | Downloads the resource and saves it with its original filename (`index.html`) in the current directory. |
| **Silent Output** | `curl -s -O inlanefreight.com/index.html` | Performs the download silently, suppressing status messages and progress bars. |
| **Help/Options** | `curl -h` | Displays a summary of all available options/flags. |

#### **Handling HTTPS & Security** **HTTP Drawbacks:** All data is transferred in **clear-text**, making it vulnerable to sniffing and **Man-in-the-Middle (MiTM) attacks** where an attacker intercepts communication.

**HTTPS Solution:** Data is **transferred in an encrypted format** using TLS/SSL.

> **Redirection Note:** If a user types `http://` for a site that enforces HTTPS, the server sends a **301 Moved Permanently** response on port 80 to redirect the client to the secure **port 443**.

| Action | `curl` Command | Description |
| --- | --- | --- |
| **Skip Certificate Check** | `curl -k https://www.inlanefreight.com` | The `-k` (insecure) flag allows `curl` to proceed when encountering an invalid or self-signed SSL/TLS certificate, common in testing environments. |

---

### 3. Analyzing HTTP Requests and ResponsesUnderstanding the full request and response is crucial for analyzing how a web application works and identifying potential vulnerabilities.

| Action | `curl` Command | Output Displayed |
| --- | --- | --- |
| **Verbose Output** | `curl -v inlanefreight.com` | Displays the full communication, including connection attempts, sent request headers, and received response headers. |
| **More Verbose** | `curl -vvv inlanefreight.com` | Shows an even more verbose output, often including internal processing details. |
| **Response Headers Only** | `curl -I https://www.inlanefreight.com` | Sends a **HEAD** request and only displays the **response headers**. |
| **Headers & Body** | `curl -i https://www.inlanefreight.com` | Displays **both the response headers and the response body**. |

#### **Manipulating HTTP Headers**Headers contain metadata about the request or response. Pen-testers often manipulate request headers to test security controls.

| Header Action | `curl` Command | Description |
| --- | --- | --- |
| **Set Custom Header** | `curl -H 'Custom-Header: value'` | Uses the `-H` flag to set any arbitrary request header. |
| **Set User-Agent** | `curl -A 'Mozilla/5.0'` | Uses the `-A` (Agent) flag as a shortcut to set the `User-Agent` header, often used to bypass basic bot/scanner detection. |

---

### 4. HTTP Methods and AuthenticationHTTP defines a set of **request methods** (verbs) to indicate the desired action to be performed on the identified resource.

#### **GET Method** Used to **retrieve** data from a server. Data is appended to the URL as query parameters.

| Action | `curl` Command | Description |
| --- | --- | --- |
| **Basic Auth** | `curl -u admin:admin http://<SERVER_IP>:<PORT>/` | Sends the credentials via the `-u` (user) flag. `curl` base64-encodes them and sets the `Authorization: Basic YWRtaW46YWRtaW4=` header. |
| **Manual Auth** | `curl -H 'Authorization: Basic YWRtaW46YWRtaW4=' http://<SERVER_IP>:<PORT>/` | Manually sets the `Authorization` header, bypassing the need for the `-u` flag. This is common when testing for misconfigurations. |

#### **POST Method** Used to **submit** data to be processed to a specified resource, typically for login forms or submitting data.

| Action | `curl` Command | Description |
| --- | --- | --- |
| **Send POST Data** | `curl -X POST -d 'username=admin&password=admin' http://<SERVER_IP>:<PORT>/` | `-X POST` sets the method, and `-d` (data) sends the form-encoded payload in the request body. |
| **Follow Redirects** | `curl -L http://<SERVER_IP>:<PORT>/login` | The `-L` flag tells `curl` to automatically follow HTTP 3xx redirection responses (like after a successful login). |

#### **Handling Cookies** Cookies are small pieces of data used to maintain state (like an authenticated session).

| Action | `curl` Command | Description |
| --- | --- | --- |
| **Set Cookie** | `curl -b 'PHPSESSID=...' http://<SERVER_IP>:<PORT>/` | Uses the `-b` (cookie) flag to send a specific cookie with the request, effectively persisting an authenticated session. |
| **JSON POST** | `curl -X POST -d '{"search":"london"}' -b 'PHPSESSID=...' -H 'Content-Type: application/json' http://<SERVER_IP>:<PORT>/search.php` | Example of a complex request: POST method, sending **JSON data** (`-d`), including a **session cookie** (`-b`), and setting the **Content-Type** header to inform the server about the data format. |

---

### 5. CRUD API InteractionMany modern web applications use **RESTful APIs** that map HTTP methods to **CRUD** (Create, Read, Update, Delete) operations on data resources.

| Operation | HTTP Method | Example `curl` Command (using a JSON response processor `jq`) |
| --- | --- | --- |
| **READ (Single)** | `GET` | `curl http://<IP>:<PORT>/api.php/city/london` |
| **READ (All)** | `GET` | `curl -s http://<IP>:<PORT>/api.php/city/london/ \| jq` (Note: Passing an empty string/ID often retrieves all entries). |
| **CREATE** | `POST` | `curl -X POST http://<IP>:<PORT>/api.php/city/ -d '{"city_name":"HTB_City", "country_name":"HTB"}' -H 'Content-Type: application/json'` |
| **UPDATE** | `PUT` | `curl -X PUT http://<IP>:<PORT>/api.php/city/london -d '{"city_name":"New_HTB_City", "country_name":"HTB"}' -H 'Content-Type: application/json'` |
| **DELETE** | `DELETE` | `curl -X DELETE http://<IP>:<PORT>/api.php/city/New_HTB_City` |
