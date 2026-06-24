#!/usr/bin/env python3
"""
SpringVault - Deliberately vulnerable Spring Boot Actuator mock for pentest
training.  *** INTENTIONALLY VULNERABLE - LOCALHOST TRAINING ONLY ***

A FAITHFUL stdlib mock of a Java/Spring Boot app with its Actuator endpoints
exposed (the classic real-world misconfiguration). No JVM needed — it reproduces
the fingerprints (Whitelabel Error Page, X-Application-Context header) and the
dangerous endpoints so the pipeline's stack-detection + actuator-mining can be
exercised end to end. Runs on 127.0.0.1:18805. See gabarito.json.

Planted: /actuator listing, /actuator/env (config secrets), /actuator/heapdump
(memory dump w/ secrets), /jolokia (JMX→RCE surface), /h2-console (DB console),
Whitelabel error page / stack trace (version + info disclosure).
"""
import http.server
import json
import socketserver

HOST, PORT = "127.0.0.1", 18805

ENV = {
    "activeProfiles": ["prod"],
    "propertySources": [
        {"name": "systemEnvironment", "properties": {
            "JAVA_HOME": {"value": "/usr/lib/jvm/java-17"},
            "HOSTNAME": {"value": "springvault-prod-7c9f"}}},
        {"name": "applicationConfig: [classpath:/application.yml]", "properties": {
            "spring.datasource.url": {"value": "jdbc:postgresql://db.internal:5432/vault"},
            "spring.datasource.username": {"value": "vault_app"},
            "spring.datasource.password": {"value": "Pr0d-Spring-DB!2026"},
            "app.jwt.secret": {"value": "eyJhbGciOiJIUzI1NiJ9.spring-signing-key-do-not-leak"},
            "stripe.api.key": {"value": "sk_live_LAB_FAKE_EXAMPLE_springvault_0xDEAD"},
            "aws.accessKeyId": {"value": "AKIA_LAB_FAKE_EXAMPLE_KEY"},
            "management.endpoints.web.exposure.include": {"value": "*"}}},
    ],
}

# Fake .hprof bytes with secret strings the heap-mining looks for.
HEAP = (b"JAVA PROFILE 1.0.2\x00" + b"\x00" * 48
        + b"java.lang.String\x00spring.datasource.password=Pr0d-Spring-DB!2026\x00"
        + b"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.adminSESSIONtoken.SIG\x00"
        + b"app.jwt.secret=spring-signing-key-do-not-leak\x00"
        + b"flag{heapdump_leaked_runtime_secrets}\x00" + b"\x00" * 96)

WHITELABEL = ("<html><body><h1>Whitelabel Error Page</h1>"
              "<p>This application has no explicit mapping for /error, so you are "
              "seeing this as a fallback.</p>"
              "<div id='created'>{ts}</div>"
              "<div>There was an unexpected error (type=Not Found, status=404).</div>"
              "<div>Spring Boot 2.6.6</div></body></html>")

STACKTRACE = ("<html><body><h1>Whitelabel Error Page</h1>"
              "<div>There was an unexpected error (type=Internal Server Error, status=500).</div>"
              "<pre>java.lang.NullPointerException: Cannot invoke \"String.length()\"\n"
              "\tat com.vault.api.AccountController.lookup(AccountController.java:88)\n"
              "\tat org.springframework.web.method.support.InvocableHandlerMethod"
              ".doInvoke(InvocableHandlerMethod.java:205)\n"
              "\tat org.apache.catalina.core.ApplicationFilterChain.doFilter"
              "(ApplicationFilterChain.java:189)\n</pre></body></html>")


class H(http.server.BaseHTTPRequestHandler):
    server_version = "nginx"          # front proxy; stack detected via Whitelabel body
    sys_version = ""

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json", extra=None):
        if isinstance(body, str):
            body = body.encode("utf-8", "replace")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Application-Context", "vault-api:prod:8080")  # Spring fingerprint
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        p = self.path.split("?")[0].rstrip("/") or "/"
        if p == "/":
            return self._send(200, WHITELABEL.format(ts="2026-06-24T05:00:00Z"), "text/html")
        if p == "/error" or p == "/account":          # verbose stack trace (info disclosure)
            return self._send(500, STACKTRACE, "text/html")
        if p == "/actuator":
            base = "http://localhost:8080/actuator"
            return self._send(200, json.dumps({"_links": {
                "self": {"href": base},
                "health": {"href": base + "/health"},
                "env": {"href": base + "/env"},
                "heapdump": {"href": base + "/heapdump"},
                "mappings": {"href": base + "/mappings"},
                "configprops": {"href": base + "/configprops"},
                "beans": {"href": base + "/beans"},
                "threaddump": {"href": base + "/threaddump"}}}))
        if p == "/actuator/health":
            return self._send(200, json.dumps({"status": "UP"}))
        if p == "/actuator/env":
            return self._send(200, json.dumps(ENV))
        if p == "/actuator/heapdump":
            return self._send(200, HEAP, "application/octet-stream",
                              {"Content-Disposition": "attachment;filename=heapdump"})
        if p == "/actuator/mappings":
            return self._send(200, json.dumps({"contexts": {"application": {"mappings": {
                "dispatcherServlet": [{"handler": "AccountController#lookup(String)",
                                       "predicate": "{GET /account}"}]}}}}))
        if p == "/actuator/configprops":
            return self._send(200, json.dumps({"contexts": {"application": {"beans": {
                "spring.datasource-org...": {"properties": {
                    "password": "Pr0d-Spring-DB!2026"}}}}}}))
        if p in ("/jolokia", "/jolokia/list"):
            # JMX over HTTP exposed -> read/invoke MBeans (RCE surface, e.g. via reloadByURL)
            return self._send(200, json.dumps({"request": {"type": "list"}, "value": {
                "java.lang": {"type=Memory": {"op": {"gc": {}}}},
                "ch.qos.logback.classic": {"Type=ch.qos.logback.classic.jmx.JMXConfigurator": {
                    "op": {"reloadByURL": {"args": [{"name": "url", "type": "java.net.URL"}]}}}}},
                "status": 200}))
        if p == "/h2-console" or p == "/h2-console/login.do":
            # H2 web console exposed -> JDBC URL RCE (CREATE ALIAS ... runtime exec)
            return self._send(200, "<html><body><h1>H2 Console</h1>"
                "<form><input name='url' value='jdbc:h2:mem:vault'>"
                "<input name='user' value='sa'><input name='password' value=''>"
                "<button>Connect</button></form></body></html>", "text/html")
        # default: Spring Whitelabel 404
        return self._send(404, WHITELABEL.format(ts="2026-06-24T05:00:00Z"), "text/html")


class TServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    srv = TServer((HOST, PORT), H)
    print(f"SpringVault (vulnerable Spring Boot Actuator mock) on http://{HOST}:{PORT}  --  Ctrl+C to stop")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
