#!/usr/bin/env python3
"""
classify.py — HackerDummy's STANDALONE vulnerability taxonomy.

Maps a free-text finding title (whatever your AI/agent calls a vuln) to a
canonical class key, so findings from ANY tool — Claude, GPT/Codex, Cursor,
a local LLM, a custom plugin — can be scored against the labs' answer keys
without forcing the tool to know our class names.

It is self-contained (pure stdlib `re`) and has NO dependency on any specific
pentest tool. The class keys here ARE the benchmark's contract; the per-lab
`gabarito.json` files use the same keys.

Usage:
    from classify import classify
    classify("SQL Injection (auth bypass)")  -> "sqli"
    classify("Exposed Redis without auth")   -> "exposed-service"

Order matters: more specific patterns come first so they win over generic ones
(e.g. `actuator` before `rce`; `default-creds` before `creds`; `stored-xss`
before `xss`; `no-rate-limit` before `graphql`).
"""
import re

# (regex, canonical_class_key) — first match wins.
TAXONOMY = [
    (r"nosql.?inj|no-?sql inj|mongo.*inject|inject.*mongo|operator injection|nosql.*operator", "nosqli"),
    (r"ldap inject|ldap.?injection|inje[cç].*ldap", "ldap-injection"),
    (r"xpath inject|xpath.?injection|inje[cç].*xpath", "xpath-injection"),
    (r"\bssi\b\s*(injection|inject)|server.?side include|\.shtml|edge.?side include", "ssi-injection"),
    (r"csv inject|formula inject|csv.*formula|formula.*csv|spreadsheet inject", "csv-injection"),
    (r"sql.?inj|\bsqli\b|union.?based|boolean.?based|error.?based|inje[cç].*sql", "sqli"),
    (r"\bactuator\b|spring boot actuator|jolokia|h2[\s-]?console|heapdump|jmx[\s-]?(http|over|console|exposed)", "actuator"),
    # upload before rce: an unrestricted-upload finding is class 'upload' even when the
    # title states the RCE impact ("File Upload -> RCE / webshell"). Pure command-injection
    # RCE has no upload words and falls through to 'rce'.
    (r"file.?upload|unrestricted upload|arbitrary file (upload|write|creat)|webshell|polyglot|upload.*(shell|arbitr|malicios|webshell|rce|remote code|execu)", "upload"),
    (r"\bxxe\b|xml external entit|external general entit|external.*entity injection", "xxe"),
    (r"deserializ|desserializ|insecure.*deserial|unsafe.*(pickle|unpickle|unserialize|marshal)|pickle.*load|object injection|__reduce__|unmarshal", "deserialization"),
    (r"\bssti\b|server.?side template inject|template injection|expression language inject", "ssti"),
    (r"\bimds\b|imdsv\d|instance metadata|metadata.*credential|credential.*(theft|exfil)|169\.254\.169\.254|security-credentials|instance.?role.*(credential|token)|steal.*(instance|iam|role).*(credential|token)", "creds"),
    (r"\bssrf\b|server.?side request", "ssrf"),
    (r"\blfi\b|local file incl|path traversal|directory traversal|file inclusion", "lfi"),
    (r"stored xss|persistent xss|xss armazenad", "stored-xss"),
    (r"reflect.*xss|xss reflet|cross.?site script|reflected.*script|dom.?based.?xss|dom.?xss", "xss"),
    (r"prototype pollut|proto.?pollut|__proto__|object\.prototype|constructor.*pollut", "prototype-pollution"),
    (r"\bidor\b|insecure direct object|broken object level|\bbola\b|refer[eê]ncia direta", "idor"),
    (r"\bbfla\b|broken function.?level|function.?level authoriz|missing function.?level", "bfla"),
    (r"excessive data exposure|excessive.*data exposur|oversharing|overshar.*(field|data)", "excessive-data"),
    (r"\bjwt\b|json web token|alg[\s:=\"']*none|none algorithm|jwt.*(secret|signature|forge|alg)|weak.*(signing|hmac).*secret", "jwt"),
    (r"\b2fa\b|\bmfa\b|\botp\b|one.?time.?password|two.?factor|second factor|multi.?factor", "2fa-bypass"),
    (r"user(name)? enumeration|account enumeration|enumera[çc][aã]o de usu|user.*enumerat", "user-enum"),
    (r"rate.?limit|brute.?force|for[çc]a bruta|no lockout|account lockout|excessive.*(attempts|requests)|throttl", "no-rate-limit"),
    (r"mass.?assignment|mass-assign|auto.?bind|over.?post|autobinding", "mass-assignment"),
    (r"race.?cond|\btoctou\b|time.?of.?check|check.?then.?act|double.?spend|concurren\w*.*(redeem|withdraw|transfer|purchase|spend|double|limit|bypass)|parallel.*request.*(double|race|bypass)", "race-condition"),
    # ── Mobile (Android) classes — single block before weak-crypto (hence before
    # auth/open-redirect/web-backup). deeplink before exported-component; backup-allowed
    # before insecure-storage; insecure-storage before weak-crypto. ──
    (r"android:debuggable|\bdebuggable\b|debug flag.*(true|enabled|on)|app.*debuggable", "debuggable"),
    (r"android:allowbackup|allow.?backup|\ballowbackup\b|adb backup|backup.*(enabled|allowed|permitted)|backup flag", "backup-allowed"),
    (r"intent.?redirect|intent redirection|intent\.parseuri|\bparseuri\b|deep.?link.*(redirect|forward|hijack|takeover|spoof|unvalidat|inject)|(url )?scheme.*(hijack|takeover|spoof)|app.?link.*(hijack|unverif|takeover)|implicit intent.*(forward|redirect)|task hijack|strandhogg|forwards? (an? |the )?(untrusted |attacker.?controlled )?intent", "deeplink"),
    (r"root detection|root check|\bisrooted\b|rootbeer|/system/bin/su|\bsu binary\b|emulator detection|emulator check|build\.fingerprint|anti.?frida|frida detect|anti.?debug|isdebuggerconnected|debugger.?detect|tracerpid|safetynet|play integrity|attestation.*(weak|bypass|missing)|tamper.?(detect|check|proof)|(root|emulator|frida|debug|tamper).*(detect|check).*(bypass|weak|naive|trivial|single|easily|defeat)|bypassable (root|anti|tamper|protection|rasp)|(weak|naive|trivial|single.?check|easily bypass\w*).*(root|anti.?debug|anti.?frida|tamper|emulator|detection|rasp)|backdoor.*(tamper|rasp|anti.?debug|anti.?frida|root|guard)|(tamper|rasp|guard|anti.?debug).*(backdoor|short.?circuit|soft.?toggle|disabl|skip)|\brasp\b", "weak-anti-tampering"),
    (r"android:exported|exported (activity|service|receiver|provider|component)|exported \w*(activity|service|receiver|provider)|(activity|service|receiver|provider|content provider).*(exported|no permission|without permission|sem permiss)|exported.*(component|without.*permission|no.?permission)|improperly exported", "exported-component"),
    (r"usescleartexttraffic|cleartexttrafficpermitted|cleartext traffic|clear.?text traffic|network.?security.?config.*(cleartext|permit|http)|cleartext.*(permitted|allowed|enabled|traffic|connection|http)|unencrypted (http|traffic|connection)", "cleartext-traffic"),
    (r"x509trustmanager|trust.?manager.*(empty|all|accept|trust.?all|no.?op)|trustallcerts|checkservertrusted.*(empty|return|nothing|no.?valid|does not)|allow.?all.?hostname|hostnameverifier.*(allow.?all|return true|always true|true for (all|any))|(ssl|tls|certificate|cert).*(pinning|validation).*(missing|absent|disabled|bypass|none|not (implement|enforc|valid))|accepts? (all|any) (cert|certificate)|trust.?all.*(cert|certificate)|(no|missing|disabled|absent) (certificate|cert|ssl|tls) (validation|pinning|check)|missing (certificate |cert )?pinning|pin.?set.*(malformed|typo|invalid|ignored|dead|empty)|pin.*(silently )?(ignored|dropped|not (applied|enforced))|malformed.*pin|pinning.*(malformed|misconfig|typo|dead|disabled|bypass)", "improper-tls"),
    (r"webview|addjavascriptinterface|javascriptinterface|setjavascriptenabled|setallowfileaccess|allowfileaccessfromfileurls|allowuniversalaccessfromfileurls|js bridge|javascript bridge|file.?url.*(webview|access)", "webview"),
    (r"flag.?secure|flag_secure|screenshot|screen.?(record|recording|capture|cast)|secure flag|(missing|absent|no|without|not set).*flag.?secure|recent.?apps? thumbnail|recents? thumbnail", "screenshot-allowed"),
    (r"shared.?pref\w*.*(world.?readable|plaintext|cleartext|mode_world|unencrypt|sensitive|token|password|secret|pii|pan)|mode_world_readable|world.?(readable|writable).*(pref|file|storage|db)|plaintext.*(sqlite|database|\.db\b|shared.?pref|prefs)|(sqlite|database|\.db\b).*(plaintext|unencrypt|cleartext|sensitive|pii|no.?encrypt|sqlcipher)|insecure (local )?(data )?storage|sensitive data.*(stored|saved|at rest).*(plaintext|cleartext|unencrypt)|stores?.*(token|password|\bpin\b|pii|card|pan|credential).*(plaintext|cleartext|unencrypt|shared.?pref|sqlite|external storage)|external storage.*(secret|token|sensitive|password|pii|credential)", "insecure-storage"),
    (r"logcat|log\.[dveiw]\b|android\.util\.log|(token|password|secret|credential|session|\bpan\b|card (number|pan)|\bpii\b|\bcpf\b).*(logged|written to (the )?log|leaked? (to|via|into) (the )?log)|sensitive (data|info\w*).*(logged|in (the )?logs?|logcat)", "sensitive-log"),
    (r"unsalted|\bmd5\b|\bsha1\b|weak.*(hash|crypto|cipher)|insecure.*(password storage|hash)|plaintext password|sem salt|\becb\b|aes/ecb|ecb mode|\bdes\b|\b3des\b|triple.?des|\brc4\b|no.?padding|static iv|fixed iv|null iv|zero iv|hardcoded iv|reused iv|hardcoded (aes|des|encryption|crypto|cipher|secret) key|(aes|des|encryption|cipher) key.*hardcod", "weak-crypto"),
    (r"session fixation|session.*(not invalidat|never.*expir|without expir|no expir|does not expir|fixa)|(token|session).*(without expir|no expir|never expir|no invalidation|no logout)|not invalidated.*(session|token|logout)|no logout endpoint|predictable.*(session|remember|cookie)|remember.?me", "session"),
    (r"\bcsrf\b|cross.?site request forgery|cross-site request|missing.*(anti.?csrf|anti.?forgery|csrf token|state param)|state param.*(missing|not (validat|requir|bound)|csrf)|oauth csrf|login csrf|samesite.*(missing|none)|no anti.?csrf", "csrf"),
    (r"authentication bypass|auth(entication)? bypass|login bypass|bypass.*authentica|type.?juggl|magic hash|loose compar(e|ison)|strcmp.*bypass|saml.*(bypass|signature|assertion|forge)|signature (bypass|strip|exclusion|wrapping)|signature wrapping|\bxsw\b|assertion (forge|inject|tamper|strip|replay)|unsigned assertion|\bpkce\b|code.?(challenge|verifier)|authorization code (reuse|replay|inject)|code reuse|client authentication (not|missing)|missing client auth|oauth.*(downgrade|reuse|replay|code inject)|password reset|reset token|broken authentication|weak.*(password )?recovery|account takeover|forgot password", "auth"),
    (r"(exposed|expos[ti]\w*).*(redis|elasticsearch|elastic|mongodb|mongo|couchdb|couch|docker|memcached|mysql|postgres|mssql|kibana|jenkins|rabbitmq|kafka|zookeeper|\bftp\b|telnet|\bsmb\b|\brdp\b|\bvnc\b|\bnfs\b|ldap)|(redis|elasticsearch|mongodb|couchdb|memcached|docker (engine )?api).*(no auth|without auth|sem auth|admin party|unauthenticated|exposed)|unauthenticated (network )?service|admin party", "exposed-service"),
    (r"default credential|default password|credenciais? padr[aã]o|senha padr[aã]o|admin/admin|weak default|default login|hardcoded credential|no password set", "default-creds"),
    (r"cors (misconfig|misconfiguration)|cross.?origin.*(misconfig|reflect|wildcard|null origin)|access.?control.?allow.?origin.*(reflect|\*|null)|origin.*reflect.*credential|\bcors\b.*(reflect|null origin|wildcard|credential)", "cors-misconfig"),
    (r"host header (injection|poison)|host.?header.?injection|x-forwarded-host|password reset poison|reset.*link.*host|host header.*(trust|inject|reset)", "host-header-injection"),
    (r"\bsmuggl|request smuggl|response smuggl|\bcl\.?te\b|\bte\.?cl\b|\bte\.?te\b|http desync|request desync|chunked.*content.?length.*(conflict|desync|smuggl)", "smuggling"),
    (r"\bcrlf\b|response splitting|http response split|carriage return.*line feed|cr.?lf inject|header inject.*(crlf|newline|response)", "crlf"),
    (r"cache poison|web cache (poison|decept)|unkeyed (header|input|param)|cache.*(poison|decept)", "cache-poisoning"),
    (r"graphql.*introspect|introspection (enabled|exposed|habilitada|on|ativ)|\b__schema\b|\b__type\b|graphql schema (expos|leak|dump)", "graphql"),
    (r"denial of service|\bdos\b|resource (exhaustion|consumption)|uncontrolled resource|query (depth|complexity)|(depth|complexity) (limit|attack|bomb)|amplification", "dos"),
    (r"open.?redirect|unvalidated redirect|redirect.*unvalidat|url redirection|redirect.*untrusted", "open-redirect"),
    (r"\.git\b|git.?expos|svn.?expos|reposit[oó]rio.*expos|source.*repo|version.?control.*expos", "scm"),
    (r"web\.config|connection string|machinekey|appsettings.*secret", "web-config"),
    (r"backup.*(dir|expos|arquivo|file)|\bbkp\b|\.bak\b|dump.*expos|sql.?dump|database (backup|dump)|\.sql\b.*(expos|public|access)", "backup"),
    (r"directory listing|index of|listagem de diret|autoindex", "dir-listing"),
    (r"phpinfo", "phpinfo"),
    (r"admin panel|painel admin|management interface|interface de gerenc|phpmyadmin|tomcat manager|unauth.*admin", "admin-panel"),
    (r"clickjack|x-frame|frame.?ancestors|frame.?busting", "clickjacking"),
    (r"http trace|trace.*habilit|\bxst\b|cross.?site tracing", "trace"),
    (r"cookie.*(flag|secure|httponly|samesite)|insecure.*cookie|sem flag", "cookie"),
    (r"security header|cabe[cç]alho.*segur|content.?security.?policy|\bcsp\b|\bhsts\b|x-content-type|referrer.?policy|permissions.?policy|strict.?transport|x-frame-options|missing.*header", "headers"),
    (r"\beol\b|end.?of.?life|outdated|unsupported|sem patches|out of date|legacy.*version|fim de vida", "eol"),
    (r"version disclos|disclosure de vers|vers[aã]o.*expos|x-aspnet-version|x-powered-by|software.*banner", "version"),
    (r"credential|senhas|password.*file|creds.*expos|plaintext.*pass|cred.*expos|arquivo.*senha|\.env\b|environment file|secrets?.*(expos|leak|disclos|hardcod|in (the )?(apk|dex|strings|assets|smali|source|code))|api.?key.*(expos|leak|hardcod|in (the )?(apk|dex|strings|assets|smali|code))|secret.*disclosure|hardcoded secret|hard.?cod.*(secret|api.?key|token|\bkey\b|credential)", "creds"),
    (r"missing authentication|no authentication required|unauthenticated access|authentication not required|broken access control|missing authoriz|missing object.?level author", "idor"),
    # rce is the LAST impact class: "<X> -> RCE" keeps root cause X (every specific
    # root cause that leads to RCE is above). Only pure command-injection lands here.
    (r"\brce\b|remote code|command inj|os command|code execution|inje[cç].*comando", "rce"),
    (r"info.*disclos|information disclosure|path disclos|internal path|caminho.*interno|topology disclos|internal (host|hostname|ip|endpoint|topolog|network)|(hostname|endpoint|url).*(internal|homolog|pre.?prod|teste\.internet)|vazamento|verbose error|erro verboso|stack.?trace|traceback|debug mode|field suggestion|unhandled exception|trace\.axd|asp.?net.*trace|\belmah\b|customerror|yellow screen of death", "info-disc"),
]

_COMPILED = [(re.compile(rx, re.I), key) for rx, key in TAXONOMY]

# All canonical class keys, for documentation / validation.
CLASS_KEYS = [key for _, key in TAXONOMY] + ["other"]


def classify(text):
    """Return the canonical class key for a free-text finding title/description."""
    t = text or ""
    for rx, key in _COMPILED:
        if rx.search(t):
            return key
    return "other"


if __name__ == "__main__":
    import sys
    for arg in sys.argv[1:]:
        print(f"{arg!r} -> {classify(arg)}")
