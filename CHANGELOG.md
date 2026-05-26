# Changelog — ouistiti (v3.4.0 → v3.6.0)

## New Features

- **Token**: improves token verification (unknown user, redundancy…), accepts token time sliding.
- **TOTP / MFA**: support for Time-based One Time Password (RFC 6238) with registry URL, multi-issuer management per session, dedicated token endpoint (`token_ep`), JWT vs generic token selection.
- **www-form authentication**: new authentication mode via HTML form (`application/x-www-form-urlencoded`).
- **Secure cookies**: `Secure` and `SameSite` flags; domain removed for localhost; `noredirect` option and `signin` as unprotected URL.
- **`mod_signature` module** (new): partial support for RFC 9421 (HTTP Message Signatures).
- **Stable WebStream**: module promoted from staging to `src`; multi-configuration support and htaccess API integration.
- **Document**: `POST` to modify a file, symlink creation via `PUT`, `notime` option for directory listing.
- **Dirlisting**: home directory support, `ctime` added, separated into an independent module.
- **Vhost**: multi-file configuration support, server groups, dynamic root change during a request.
- **Userfilter**: new `reapproving` role, configurable allowed HTTP methods per server.
- **authmngt**: new backend lifecycle API (create/destroy/setup/cleanup), full issuer management via REST, password encryption, password status in responses.
- **Python**: Django API support, asynchronous response handling, module reload on each request.
- **Main application**: new public cookie API (`ouimessage_setcookie`), `--logfile` option with max size, dependency check on module load.

## Major Internal Refactoring

- **`string_t` migration**: replacement of `searchexp` across all modules (auth, authmngt, document, redirect, vhost, cors, webstream, websocket, cgi, userfilter, clientfilter, forward, htaccess, server). New primitives: `match`, `unroot`, `decodeurl`, `contain`, `replace`, `endwith`, `compare`, `storage`, `browse`, `into`, `value`, `unquote`, `slice`, `writeable`.
- **Auth — mod/ctx separation**: `mod` and `ctx` data decoupled for Basic, Digest, TOTP and JWT; token managed as a dedicated object; SQLite opened per module.
- **libhttpserver 3.6**: major update (OpenSSL 3.0, vhost fixes, CGI message length).

## Notable Security Fixes

- Authentication refused if the `Host` header is invalid.
- Timing-safe string comparison in auth.
- Path hardening: `unroot` blocks `..` and `//` sequences.
- Hostname validation via regexp in vhost, cors and auth.
- Stack-overflow fix in the document module.

---

# Changelog — ouistiti (v3.2.0 → v3.4.0)

## New Features

- **`mod_forward` module** (new): forwards requests to another server.
- **WebSocket**: periodic PING added (5s timeout); socket open / execution separated; `protocol` header transmitted on connection; TEXT data no longer includes the trailing null character.
- **WebStream**: `multipart/mixed` stream support with random boundary, `Date` header, delay between parts; socket open / execution separated; mjpeg tools added.
- **Document**: new `htaccess` mechanism (deny/allow); `defaultpage` redirected via the redirect module; support for a list of configurations; removal of `others` rights on created files; dirlisting refactored using `scandir`.
- **Vhost**: support for multiple vhosts on the same server.
- **CORS**: `Vary` header added.
- **CGI**: separate IN/OUT stream handling; configurable timeout from the config file; binary data support; use of `execveat` (valgrind compatibility); `path_info`/`cgipath` fix.
- **Python**: new module (staging); content handling in request/response; scripts configurable from the config file.
- **Auth**: new authz context created per client; authorization length and token handling; revised session storage (per-entry info as string); expired session removal; `realm` moved to the main config section.
- **TLS/OpenSSL**: openssl module promoted from staging to `src`; improved error handling; `pemfile` renamed to `keyfile`; SSL configuration initialized at module creation.
- **Main application**: shared string collections between modules; `FILE_CONFIG=n` support; correct destruction of a multi-server config; 256-character limit for unknown strings.
- **`root` option**: new global server option usable by all modules.

## Major Internal Refactoring

- **Migration to length-aware APIs** (`INFO2`, `REQUEST2`, `auth_info2`, `httpmessage_appendheader2`, `httpmessage_content2`): replacement of `strlen` and `str*` calls with new APIs that explicitly handle lengths, across all modules (auth, cgi, redirect, server, dirlisting, mbedtls).
- **`string_t` in auth**: configuration, tokens, session and digest migrated to `string_t`.
- **Module API**: new unified configuration API for all modules; static module initialization updated.
- **Cookie**: new `get`/`set` API.

## Notable Fixes

- Fix for Digest nonce generation.
- Fix for `str_tls` length in mbedtls.
- Fix for a potential bug in password parsing (`OUTBOUND`).
- Fix for unprotected URL without `Authorization` header.
- libhttpserver update (v3.4, TCP wait timeout).

---

# Changelog — ouistiti (v3.0.0 → v3.2.0)

## New Features

- **Vhost**: new stable module (promoted from staging); refactored with new architecture; support for multiple vhosts on the same server; vhost authentication tests added.
- **Auth**: user status management (`approving`, `reapproving`, `activated`); session reset on logout; user information removed for unauthenticated connections; `redirect_uri` disabled on protected URIs (logout); token verification from cookies (multi-cookies); auth headers exported on CORS requests.
- **authmngt**: new user management module via REST (list, create, modify, delete); automatic DB generation if absent; user activation/deactivation; `GET /auth/mngt/all` to list users.
- **userfilter**: new stable module (promoted from staging); REST API for PUT/DELETE filters; GET returns the list of rules; new default filters.
- **CORS**: `Origin` verification on protected methods; `Allow-Origin` header with full request URL; `HEADERS` header for each request with `Origin`; `Allow-Origin` set before authentication.
- **Upgrade**: new module allowing socket upgrade to unix/inet; inet socket support.
- **Cookie**: `sameSite=strict` flag added.
- **Main application**: `OUISTITI_MODULES_PATH` environment variable; `-M` option to define multiple module paths; `init.d` support (start/stop script directory); `-C` option to display the configuration; `-w` option to set the working directory; automatic module loading from `PKGLIBDIR`.
- **WebSocket**: TCP URI support; fix for sending empty string; proxy stopped on `close` message.

## Major Internal Refactoring

- **Module architecture**: each module now integrates its own `configure` function (removal of centralized configuration in `main`); new `configure` callback in the module object.
- **Session API**: replacement of `group`, `home`, `token`… with `setsession`; direct storage of session info field by field.
- **Memory management**: systematic resource release (config, modules, scandir, sockets) on destruction.
- **Config/startup separation**: `loadserver` and `setmodules` decoupled; server configuration loaded independently.

## Notable Fixes

- Fix for Digest nonce generation.
- Fix for file access with double `/` in the URI.
- Fix for URL decoding in `userfilter` and `authmngt`.
- Fix for memory leaks in redirect, document, cgi, auth.
- Fix for SQLite initialization (root id at 0, default status).

---

# Changelog — ouistiti (v2.4.2 → v3.0.0)

## New Features

- **authmngt**: new user management module with SQLite support (add, modify, delete users and passwords); full REST API.
- **Auth**: JWT-signed tokens; JWT verification on receipt (`checktoken`); passwords stored as SHA-256 in SQLite; `status` field in JWT; `protect` option to force a 403; `noredirect` option to disable redirect to login; `redirect_uri` option for relocation (302); OAuth2 support for token URI generation; SQLite interface for user management.
- **userfilter**: new module (promoted from staging); filtering by URI and by group.
- **Upgrade**: new module for socket upgrade to unix.
- **Cookie**: `sameSite=strict` flag added.
- **Main application**: `-M` option for module paths; loading from `PKGLIBDIR`; PID file locking; daemon support via `daemonize`; socket kept open when daemonizing.
- **WebStream**: root URI check at creation; improved mjpeg and streamer utilities.
- **WebSocket**: TCP URI support; URI check at initialization.
- **TLS**: `wait` callback added to the protocol; connection closed on disconnected client.

## Major Internal Refactoring

- **Module architecture**: complete configuration refactoring — each module has its own `configure` function moved out of `main`; new callback in the module object.
- **Session API**: replacement of individual fields (`group`, `home`, `token`…) with a unified `setsession` API.
- **Length types**: widespread replacement of `int` with `size_t` for lengths throughout the codebase; replacement of `setbuf` with `setlinebuf`.
- **Memory management**: systematic release across all modules (config, modules, scandir, sockets).

## Notable Fixes

- Fix for double-dot (`..`) access in URIs (handled by httpserver).
- Fix for CGI data length.
- Fix for `path_info` and `cgipath` in CGI.
- Fix for out-of-bounds memory access in CGI.
- Fix for JWT token length calculation (integer instead of float).
- Fix for Digest nonce generation.

---

# Changelog — ouistiti (v2.2.0 → v2.4.2)

## New Features

- **Auth**: tokens signed and verified by `mod_auth`; JWT verification (expiration); full Digest support (time-based nonce, accelerated parsing, MD5 support by default, URL with query support); unix password expiration check; standalone bearer authentication (JWT not required); `chown` option to change process owner.
- **Document**: `PUT` creates or appends to a file; `201` response on REST success; `dirlisting` with `readdir_r` (thread-safe); transition to `openat` for long paths.
- **CGI**: transition to `openat`; separation of response functions; strict RFC 3875 compliance; environment variable duplication from the config file.
- **WebStream**: transition to `openat` + `fchdir`; random boundary in `multipart/mixed`.
- **Config**: new option parser; removal of the limit on the MIME type list.
- **Main application**: new `auth_setowner` function.

## Internal Refactoring

- Refactoring of hash management in auth.
- Refactoring of authorization verification in auth.
- Separation of redirect configuration code.
- Alignment with the new `appendheader` API from libhttpserver.
- New `searchexp` API returning the remainder of the wildcard match.

## Notable Fixes

- Digest fix: NULL character at end of username; nonce large enough.
- CGI fix: unexpected character at end of `cgipath`; data length.
- Auth bearer fix: `user` must be set by authz.
- Document fix: length check before using strings.
