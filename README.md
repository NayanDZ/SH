# HTTP Security Headers

## X-Frame-Options ▶️ [Prevent Clickjacking Vulnerability](https://github.com/NayanDZ/clickjacking/)

``` 
X-Frame-Options: DENY | SAMEORIGIN | ALLOW-FROM URL 
```

Instead of X-Frame-Options, the Content-Security-Policy frame-ancestors directive can be used for clickjacking

## Content Security Policy ([CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)) ▶️ [Prevent Clickjacking & XSS Vulnerability]
CSP provide extra layer of security against XSS, Clickjacking, and Frame Injection.

``` 
Content-Security-Policy: frame-ancestors 'none'; // No URL can load the page in an iframe.
```
```
Content-Security-Policy: frame-ancestors 'self'; // Serves the same function as the SAMEORIGIN parameter.
```
```
Content-Security-Policy: script-src 'self' https://apis.google.com     // XSS Prevention
```

## X-XSS-Protection ▶️ [Prevent XSS Vulnerability](https://github.com/NayanDZ/XSS)
X-XSS-Protection allows developers to change the behavior of the Reflected XSS security filters. These filters aim to detect dangerous HTML input and either prevent the site from loading or remove potentially malicious scripts.

```
X-XSS-Protection: 0                           -> xss filter disabled
X-XSS-Protection: 1                           -> xss filter enabled and sanitized the page if attack detected
X-XSS-Protection: 1; mode=block               -> xss filter enabled and prevented rendering the page if attack detected
X-XSS-Protection: 1; report=<reporting-uri>   -> xss filter enabled and reported the violation if attack detected
```

## X-Content-Type-Options
This HTTP header is typically used to control the MIME Type Sniffing function in web browsers. MIME Type Sniffing is a content evaluation function used by browsers when the content type is not specified. Basically, if the Content-Type header is blank or missing, the browser 'sniffs' the content and attempts to display the source in the most appropriate way.

To prevent the browser from sniffing the page's content and deciding on which MIME type to use, use the X-Content-Type-Options header with the nosniff directive:
```
X-Content-Type-Options: nosniff
```

## X-Download-Options
The X-Download-Options header can be used download the requested data instead of viewing it in the browser

```
X-Download-Options: noopen
```

## HTTP Strict Transport Security (HSTS)
HSTS is a mechanism that forces browsers to use a secure web connection.
  - Convert all requests to an HTTPS connection
  - In case of a certificate related error such as an expired certificate, prevent the user from browsing the website anyway
```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
``` 

## Referrer-Policy
The Referrer-Policy header governs which referrer information, sent in the Referer header, should be included with requests made.

The Referer header will be added to requests made for style, image, script loads, and form submissions
```
Referrer-Policy: no-referrer
```

## Access-Control-Allow-Origin ▶️ Cross-Origin Resource Sharing ([CORS](https://github.com/NayanDZ/CORS))

The Access-Control-Allow-Origin response header indicates whether the response can be shared with requesting code from the given origin.

```
Access-Control-Allow-Origin: https://developer.mozilla.org
```

## Refrence

- https://www.netsparker.com/whitepaper-http-security-headers/#HTTPPublicKeyPinning

