# DARKCAT – Dark Web Recon Claw
```text
                                __
                         _,-;''';`'-,.
                      _/',  `;  `;    `\
      ,        _..,-''    '   `  `      `\
     | ;._.,,-' .| |,_        ,,          `\
     | `;'      ;' ;, `,   ; |    '  '  .   \
     `; __`  ,'__  ` ,  ` ;  |      ;        \
     ; (6_);  (6_) ; |   ,    \        '      |       /
    ;;   _,' ,.    ` `,   '    `-._           |   __//_________
     ,;.=..`_..=.,' -'          ,''        _,--''------''''
_pb__\,`"=,,,=="',___,,,-----'''----'_'_'_''-;''
-----------------------''''''\ \'''''   )   /'     DARKCAT
                              `\`,,,___/__/'_____,
                                `--,,,--,-,'''\
                               __,,-' /'       `
                             /'_,,--''
                            | (           Dark web recon claw
                             `' 
```

DARKCAT is a proof-of-concept command-line tool for passive dark web
reconnaissance in a digital forensics context.

The tool is written in Rust and performs controlled HTTP requests to
.onion services via the Tor network using a SOCKS5 proxy.

---

## Purpose

The purpose of DARKCAT is to demonstrate how dark web reconnaissance
can be performed in a controlled, passive and forensics-oriented way.

Dark web data can serve as a secondary source of indicators in digital
forensics investigations, for example when assessing potential data
leaks, exposed services or historical compromises.

---

## Scope and Limitations

DARKCAT is intentionally limited to passive reconnaissance.

The tool performs a single HTTP GET request and does not crawl,
authenticate, exploit vulnerabilities or interact with dynamic
application functionality.

This design minimizes impact on the target system and aligns with
forensic principles of non-destructive evidence collection.

---

## Architecture Overview

DARKCAT is executed in an isolated environment consisting of:

- An Ubuntu-based virtual machine
- A Docker container encapsulating the application and Tor
- The Tor network accessed via a SOCKS5 proxy

This layered setup reduces risk and improves reproducibility.

---

## Features

- Passive scan of .onion and clearnet URLs
- Automatic routing through Tor
- HTTP response inspection
- Tor connectivity verification
- Simple and reproducible CLI workflow

---

## Usage

Get the repository:

```bash
git clone https://github.com/Ryzaxd/DARKCAT.git
```

Go to it's folder:

```bash
cd DARKCAT
```

Build the Docker image:

```bash
docker build -t darkcat .
```

Check Tor connectivity:

```bash
docker run --rm darkcat status
```

Scan an onion service:

```bash
docker run --rm darkcat scan --url exampleonionaddress.onion
```

The tool automatically normalizes URLs, so both of the following are valid:

```bash
exampleonionaddress.onion
http://exampleonionaddress.onion
```
