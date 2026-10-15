# Custom HTTP Discovery Scripts for Nmap NSE

Two lightweight custom Nmap Scripting Engine (NSE) scripts for HTTP service discovery and response inspection.

## Scripts

### 1. `http-methods-detail.nse`

Sends a single HTTP OPTIONS request and reports the response status and selected headers, including `Allow`, `Public`, `DAV`, `Accept-Patch`, `Accept-Post`, `Content-Type`, `Content-Length`, `Location`, and `Server`.

The script does not probe individual HTTP methods.

### 2. `http-path-info.nse`

Inspects a small, user-controlled list of HTTP paths and reports status codes, response metadata, and redirect information.

Features include:
- HEAD requests with GET fallback when HEAD returns 405 or 501.
- A configured 1,024-byte response-body limit for GET fallback.
- Origin-relative redirect handling.
- Redirect-loop detection and a maximum of three redirects per path.
- Input validation and readable request-failure output.

## Requirements

- Nmap with the Nmap Scripting Engine.
- An HTTP service on the target port.

No external Python packages or additional runtime dependencies are required by these NSE scripts.

## Installation

Copy the `.nse` files into your Nmap scripts directory.

On a standard Windows installation:

```text
C:\Program Files (x86)\Nmap\scripts
```

Open Command Prompt and update the script database:

```cmd
"C:\Program Files (x86)\Nmap\nmap.exe" --script-updatedb
```

## Usage

Run both scripts against a known HTTP service:

```cmd
"C:\Program Files (x86)\Nmap\nmap.exe" -sT -Pn -p 8000 --script http-methods-detail,http-path-info 127.0.0.1
```

Inspect selected paths:

```cmd
"C:\Program Files (x86)\Nmap\nmap.exe" -sT -Pn -p 8000 --script http-path-info --script-args "http-path-info.paths=/|/robots.txt|/missing-page" 127.0.0.1
```

Inspect the OPTIONS response for a specific path:

```cmd
"C:\Program Files (x86)\Nmap\nmap.exe" -sT -Pn -p 8000 --script http-methods-detail --script-args "http-methods-detail.path=/" 127.0.0.1
```

Replace the target and port with the HTTP service you are authorized to inspect.

## Testing

The scripts were tested on Windows 11 with Nmap 7.991 against a local Python HTTP test server.

Observed tests included:
- OPTIONS returning HTTP 501.
- Successful and missing paths.
- Origin-relative redirects.
- Redirect-loop detection.
- Rejection of absolute redirects.
- HEAD rejection followed by GET fallback.
- Malformed HTTP responses.
- Connection drops.
- Invalid path arguments.
- Closed-port behavior.

The configured GET response-body limit should be independently verified using a response larger than 1,024 bytes before claiming that truncation has been tested.

## Relationship to built-in Nmap scripts

These scripts complement rather than replace Nmap's existing HTTP scripts.

- [`http-methods`](https://nmap.org/nsedoc/scripts/http-methods.html)
- [`http-enum`](https://nmap.org/nsedoc/scripts/http-enum.html)
- [Nmap HTTP library](https://nmap.org/nsedoc/lib/http.html)

## Project Scope

These scripts focus on HTTP discovery and response information. They are not general-purpose vulnerability scanners.

## Acknowledgements

- School of Computer Science and Engineering (SCOPE), Vellore Institute of Technology Chennai.
- Dr. T. Subbulakshmi, Professor, SCOPE, VIT Chennai.
- The Nmap project and its documentation.
- Peers and other contributors who provided guidance or suggestions.
