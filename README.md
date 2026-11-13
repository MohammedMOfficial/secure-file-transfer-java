# Secure Client-Server File Transfer (Java)

A terminal-based file transfer system written in Java. Clients connect to a multithreaded server over **TLS**, register or log in, and then upload, download, list, and delete files. Users and file metadata are stored in **MySQL**. Normal users can only touch their own files, while admins can manage everyone's.

Built as a university networking project at the University of Jordan, then security-reviewed and hardened afterwards (see [Security review](#security-review)).

## Features

| Area | What it does |
|---|---|
| Transport | TLS (`SSLSocket` / `SSLServerSocket`) between client and server |
| Concurrency | Multithreaded server with a bounded worker pool and idle-connection timeout |
| Accounts | Sign up with confirmed password; login with salted PBKDF2 password hashes |
| Sessions | Random 256-bit session key issued at login and required on every request |
| Roles | `normal` (own files only) and `admin` (list, download, and delete any file) |
| Brute-force defence | 5 failed logins blocks the client's IP address for 5 minutes |
| File operations | `list`, `upload`, `download`, `delete`, `bye` (logout) |
| Audit trail | Every login, logout, upload, download, and delete is written to a `Log` table |

## Architecture

```
 ┌──────────────┐        TLS (TCP :2121)        ┌─────────────────────────┐        JDBC        ┌─────────┐
 │  ClientMain  │ ────────────────────────────► │ ServerMain              │ ─────────────────► │  MySQL  │
 │ (terminal)   │ ◄──────────────────────────── │  └─ HandleClient/thread │ ◄───────────────── │ zt_ftp  │
 └──────────────┘                                │      ├─ DBHandler       │                    └─────────┘
                                                 │      ├─ PasswordHasher  │
                                                 │      └─ FileSecurity    │        files on disk: server_files/<user>/
                                                 └─────────────────────────┘
```

**Request flow:** connect (TLS) → `signup` or `login` → server returns a session key → every later request carries `sessionKey + operation` → server checks the key, checks authorisation, performs the operation, and logs it.

Packages and classes (`src/main/java`):

- `server/ServerMain`: opens the TLS listener and hands each client to a worker pool.
- `server/HandleClient`: the protocol: signup, login, and the logged-in command loop.
- `server/DBHandler`: all SQL, using prepared statements only.
- `server/PasswordHasher`: PBKDF2 hashing, salt and session-key generation, constant-time comparison.
- `server/FileSecurity`: validation of usernames and file names, and safe path resolution.
- `server/CreateAdmin`: command-line helper that creates an admin account.
- `client/ClientMain`: the interactive terminal client.

Database schema: [`sql/schema.sql`](sql/schema.sql) (tables `Userinfo`, `Sessionkey`, `File`, `Log`, `Block`). The original planning notes are in [`docs/original-design-notes.md`](docs/original-design-notes.md).

## Getting started

**Requirements:** JDK 17 or newer, MySQL 8, and the [MySQL Connector/J](https://dev.mysql.com/downloads/connector/j/) JAR (place it in a `lib/` folder).

### 1. Create the database
```sql
SOURCE sql/schema.sql;
```

### 2. Create a TLS certificate (self-signed, for local use)
```bash
keytool -genkeypair -alias server -keyalg RSA -keysize 2048 -validity 365 \
        -dname "CN=localhost" -ext san=dns:localhost,ip:127.0.0.1 \
        -keystore server.jks -storepass CHANGE_ME -keypass CHANGE_ME

keytool -exportcert -alias server -keystore server.jks -storepass CHANGE_ME -file server.cer
keytool -importcert -noprompt -alias server -file server.cer -keystore trust.jks -storepass CHANGE_ME
```
`server.jks` stays on the server, and `trust.jks` goes to clients. **Never commit either file** (they are in `.gitignore`).

### 3. Compile
```bash
# Linux / macOS
mkdir -p out && javac -d out -cp lib/mysql-connector-j-8.4.0.jar $(find src -name "*.java")
```
```powershell
# Windows PowerShell
mkdir out -Force; javac -d out -cp lib\mysql-connector-j-8.4.0.jar (Get-ChildItem -Recurse src -Filter *.java).FullName
```

### 4. Configure and run the server
Secrets come from environment variables, never from the source code.

```powershell
# Windows PowerShell (use `export VAR=value` and `:` instead of `;` on Linux/macOS)
$env:DB_PASSWORD       = "your-mysql-root-password"
$env:KEYSTORE_PATH     = "server.jks"
$env:KEYSTORE_PASSWORD = "CHANGE_ME"
java -cp "out;lib\mysql-connector-j-8.4.0.jar" server.ServerMain
```

| Variable | Default | Purpose |
|---|---|---|
| `DB_URL` | `jdbc:mysql://localhost:3306/zt_ftp?...` | JDBC connection string |
| `DB_USER` / `DB_PASSWORD` | `root` / *(empty)* | Database credentials |
| `KEYSTORE_PATH` / `KEYSTORE_PASSWORD` | required | Server TLS certificate |
| `PORT` | `2121` | Listening port |
| `MAX_CLIENTS` | `50` | Worker thread pool size |

### 5. (Optional) Create an admin account
Admins cannot sign up through the client, so create one from the command line. This is the only place an admin password is ever typed:
```powershell
java -cp "out;lib\mysql-connector-j-8.4.0.jar" server.CreateAdmin admin YourStrongPassword
```

### 6. Run the client
```powershell
$env:TRUSTSTORE_PATH     = "trust.jks"
$env:TRUSTSTORE_PASSWORD = "CHANGE_ME"
java -cp out client.ClientMain            # or: client.ClientMain <host> <port>
```
Downloaded files are saved to your `Downloads` folder. Uploaded files are stored on the server under `server_files/<username>/`.

### Example session
```
login | signup | exit
--> signup
Username: alice
Password: ********   Confirm password: ********
Account created. You can log in now.

--> login
You are logged in as alice.
list | upload | download | delete | bye (logout)
--> upload
Path of the file to upload: C:\docs\report.pdf
Uploaded: report.pdf
--> list
report.pdf
```

## Security review

The first version of this project worked, but a self-review found several weaknesses. Each is now fixed:

| Issue found | Risk | Fix |
|---|---|---|
| SQL built by string concatenation | SQL injection | Every query is a `PreparedStatement` with bound parameters |
| Client-supplied file names used directly in paths | Path traversal (`../../x`) could write or read outside the user's folder | Strict name validation plus canonical-path check (`FileSecurity`) |
| A normal user could name another user as the file "owner" in a delete request | Broken access control | The server ignores the owner for non-admins and uses the logged-in user |
| Login block used an IP address supplied by the client | Lockout bypass | Block is checked and recorded using the real socket address |
| Custom salt-interleave plus one round of SHA-256 | Fast to brute-force if the DB leaks | PBKDF2-HMAC-SHA256, 210,000 iterations, random per-user salt, constant-time compare |
| After a block expired, server and client went out of step | Hang / deadlock | Expired blocks are purged before every check |
| Signup loop never exited if the user folder already existed | Hang | Signup protocol rewritten and validated |
| Failed delete sent extra messages the client did not read | Protocol desync | One reply per request, and uploads now get an explicit `ok` / `rejected` |
| Server looped forever after a client disconnected | CPU spin / resource leak | Loop ends on I/O error and the session key is always deleted |
| Unbounded thread-per-connection, no timeouts, no upload limit | Easy denial of service | Fixed-size thread pool, 10-minute idle timeout, 100 MB upload cap |
| Hard-coded DB password, keystore name, and a demo admin hash in the README | Secrets in source control | Configuration via environment variables; `CreateAdmin` tool |
| Usernames unrestricted | Odd characters in paths and logs | Usernames limited to `[A-Za-z0-9_.-]{3,50}`; passwords at least 8 characters |

**How it was verified:** the hardened server and client were exercised end-to-end over real TLS with 27 automated checks, including path-traversal uploads, spoofed-owner deletes, wrong session keys, oversize uploads, and the 5-attempt lockout. The SQL layer needs a live MySQL server, so run through the getting-started steps once on your own machine to confirm it end to end.

## Known limitations and next steps

- **No user-level lockout**: blocking is per IP address, so users behind a shared network (NAT) share a block. A per-account counter would be better.
- **Sessions do not expire** by time. They end on logout or disconnect.
- **Files are stored unencrypted** on the server's disk, and are protected in transit by TLS only.
- **Self-signed certificate**: fine for a course project, but production would use a CA-signed certificate.
- **No automated test suite in this repo yet** (a good first contribution: JUnit tests for `FileSecurity` and `PasswordHasher`).
- **Terminal only**: no GUI, resumable transfers, or file integrity checksums.

## Technologies

Java (sockets, `javax.net.ssl`, multithreading, JDBC) · MySQL · PBKDF2 / SHA-256 · TLS · `keytool`

