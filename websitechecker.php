<?php
// website_check_full_fast.php — Passive Website Health & Hardening Checker (Web UI + CLI + CSV export)
// Fitur: WHOIS, Subdomain (crt.sh), dan "Cek Subdomain LIVE" (DNS + HTTP/HTTPS) versi CEPAT (curl_multi)
// Catatan: Hanya pemeriksaan pasif. Tidak ada payload exploit.

set_time_limit(0);
error_reporting(E_ALL & ~E_NOTICE);

function e($s){ return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
function now_iso(){ return date('c'); }

function parse_hsts_max_age(string $hstsHeader = ''): ?int {
    if (!$hstsHeader) return null;
    if (preg_match('/max-age\s*=\s*(\d+)/i', $hstsHeader, $m)) return (int)$m[1];
    return null;
}

// ========== WHOIS & SUBDOMAIN HELPERS ==========
function extract_base_domain(string $host): string {
    $host = strtolower(rtrim($host, '.'));
    if (filter_var($host, FILTER_VALIDATE_IP)) return $host;
    $labels = explode('.', $host);
    if (count($labels) <= 2) return $host;

    $multiTLD = [
        'co.id','ac.id','sch.id','or.id','go.id','web.id','my.id','biz.id',
        'co.uk','ac.uk','gov.uk','org.uk',
        'com.au','net.au','org.au',
        'co.jp','ne.jp','or.jp'
    ];
    $last2 = implode('.', array_slice($labels, -2));
    $last3 = implode('.', array_slice($labels, -3));
    if (in_array($last2, $multiTLD, true)) {
        if (count($labels) >= 3) return $last3;
    }
    return $last2;
}

/** WHOIS sederhana via whois.iana.org -> whois server TLD -> query domain */
function whois_lookup(string $domain, int $timeout = 8): string {
    $domain = trim($domain);
    if ($domain === '') return 'WHOIS: domain kosong';
    $parts = explode('.', $domain);
    if (count($parts) < 2) return "WHOIS: domain tidak valid: {$domain}";
    $tld = end($parts);

    $iana = @fsockopen('whois.iana.org', 43, $eno, $estr, $timeout);
    if (!$iana) return "WHOIS: gagal konek IANA ({$eno}) {$estr}";
    fwrite($iana, $tld . "\r\n");
    stream_set_timeout($iana, $timeout);
    $ianaResp = '';
    while (!feof($iana)) { $ianaResp .= fgets($iana, 1024); }
    fclose($iana);

    $whoisServer = null;
    if (preg_match('/^whois:\s*(.+)$/mi', $ianaResp, $m)) $whoisServer = trim($m[1]);
    if (!$whoisServer) $whoisServer = 'whois.verisign-grs.com';

    $s = @fsockopen($whoisServer, 43, $eno2, $estr2, $timeout);
    if (!$s) return "WHOIS: gagal konek {$whoisServer} ({$eno2}) {$estr2}";
    $query = (stripos($whoisServer, 'verisign') !== false) ? "domain {$domain}" : $domain;
    fwrite($s, $query . "\r\n");
    stream_set_timeout($s, $timeout);
    $out = '';
    while (!feof($s)) { $out .= fgets($s, 1024); }
    fclose($s);

    $out = trim($out);
    if ($out === '') $out = "WHOIS: kosong / dibatasi oleh registry";
    return $out;
}

/* ===========================================================
   TAMBAHAN HELPER (tanpa mengubah struktur pemanggilan)
   =========================================================== */

/** HTTP GET dengan retry, header JSON, dukung gzip, prefer IPv4 */
function http_get(string $url, int $timeout = 15, int $retries = 3): ?string {
    for ($i=0; $i<$retries; $i++) {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 8,
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_USERAGENT => 'IAIDU-Checker/1.2',
            CURLOPT_HTTPHEADER => ['Accept: application/json, */*;q=0.1'],
            CURLOPT_ENCODING => '',
            CURLOPT_IPRESOLVE => CURL_IPRESOLVE_V4,
        ]);
        $resp = @curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE) ?: 0;
        curl_close($ch);

        if ($resp !== false && $code === 200) {
            // Jika rate-limit, crt.sh kadang balas HTML—anggap gagal dan retry
            if (strpos(ltrim($resp), '<') !== 0) return $resp;
        }
        usleep(200000 + $i*300000); // backoff: 200ms, 500ms, 800ms
    }
    return null;
}

/** Normalisasi host: hapus wildcard/skema/port, filter di dalam baseDomain, unik + sort + limit */
function normalize_host_list(array $hosts, string $baseDomain, int $limit = 500): array {
    $out = [];
    $baseDomain = strtolower($baseDomain);
    foreach ($hosts as $h) {
        $h = strtolower(trim((string)$h));
        if ($h === '' || $h === $baseDomain) continue;
        $h = str_replace('*.', '', $h);
        $h = preg_replace('#^https?://#','',$h);
        $h = preg_replace('#[:/].*$#','',$h); // hilangkan port/path
        if (!str_ends_with($h, '.'.$baseDomain)) continue;
        $out[$h] = true;
        if (count($out) >= $limit) break;
    }
    $res = array_keys($out);
    sort($res);
    return $res;
}

/** Parser crt.sh: dukung JSON array maupun newline-delimited JSON */
function parse_crtsh_json(?string $resp): array {
    if ($resp === null) return [];
    $data = json_decode($resp, true);
    if (is_array($data)) return $data;
    $rows = [];
    foreach (preg_split('/\r?\n/', trim($resp)) as $ln) {
        $ln = trim($ln);
        if ($ln === '') continue;
        $j = json_decode($ln, true);
        if (is_array($j)) $rows[] = $j;
    }
    return $rows;
}

/** Cache ringan 6 jam (file di /tmp) */
function cache_get(string $key, int $ttlSeconds = 21600): ?array {
    $dir = sys_get_temp_dir() . '/iaiduchk_cache';
    if (!is_dir($dir)) @mkdir($dir, 0700, true);
    $file = $dir.'/'.sha1($key).'.json';
    if (!is_readable($file)) return null;
    if (filemtime($file) + $ttlSeconds < time()) return null;
    $data = json_decode(@file_get_contents($file), true);
    return is_array($data) ? $data : null;
}
function cache_set(string $key, array $val): void {
    $dir = sys_get_temp_dir() . '/iaiduchk_cache';
    if (!is_dir($dir)) @mkdir($dir, 0700, true);
    $file = $dir.'/'.sha1($key).'.json';
    @file_put_contents($file, json_encode($val));
}

/** Ekstrak host dari daftar URL apa pun */
function extract_hosts_from_urls(array $urls): array {
    $hosts = [];
    foreach ($urls as $u) {
        $u = trim((string)$u);
        if ($u === '') continue;
        // normalisasi cepat
        if (!preg_match('#^https?://#i', $u)) $u = 'http://' . $u;
        $p = @parse_url($u);
        if (!is_array($p) || empty($p['host'])) continue;
        $hosts[] = strtolower($p['host']);
    }
    return $hosts;
}

/** Wayback Machine (CDX) — ambil daftar original URL, lalu petik hostnya */
function fetch_wayback_hosts(string $baseDomain, int $limit = 500): array {
    // fl=original -> hanya URL asli; gzip diaktifkan oleh http_get
    $url = 'https://web.archive.org/cdx/search/cdx?url=*.' . rawurlencode($baseDomain)
         . '/*&output=json&fl=original&collapse=original&filter=statuscode:200';
    $resp = http_get($url, 20, 2);
    if ($resp === null) return [];
    $json = json_decode($resp, true);
    if (!is_array($json)) return [];
    // CDX mengembalikan array of arrays; baris pertama kadang header — amankan
    $urls = [];
    foreach ($json as $row) {
        if (is_array($row) && isset($row[0])) $urls[] = $row[0];
    }
    $hosts = extract_hosts_from_urls($urls);
    return $hosts;
}

/** AlienVault OTX Passive DNS — opsional; jika blocked/need API, fungsi ini akan kembali [] */
function fetch_otx_hosts(string $baseDomain, int $limit = 500): array {
    $url = 'https://otx.alienvault.com/api/v1/indicators/domain/' . rawurlencode($baseDomain) . '/passive_dns';
    $resp = http_get($url, 15, 2);
    if ($resp === null) return [];
    $data = json_decode($resp, true);
    if (!is_array($data) || empty($data['passive_dns'])) return [];
    $out = [];
    foreach ($data['passive_dns'] as $row) {
        if (!empty($row['hostname'])) $out[] = strtolower($row['hostname']);
        if (!empty($row['recorded'])) { /* no-op, hanya memastikan format */ }
    }
    return $out;
}

/** Mini DNS brute: cek list kandidat populer (tanpa HTTP), hanya resolusi DNS */
function dns_bruteforce_hosts(string $baseDomain, array $candidates, int $maxOut = 200): array {
    $found = [];
    foreach ($candidates as $label) {
        $host = strtolower($label . '.' . $baseDomain);
        if (checkdnsrr($host, 'A') || checkdnsrr($host, 'AAAA') || checkdnsrr($host, 'CNAME')) {
            $found[] = $host;
            if (count($found) >= $maxOut) break;
        }
    }
    return $found;
}

/** Daftar kandidat umum (disesuaikan konteks Indonesia / instansi) */
function common_idgov_candidates(): array {
    return [
        // umum
        'www','mail','webmail','smtp','pop','imap','mx','ns1','ns2','vpn','intranet','portal','api','cdn',
        // layanan publik
        'ppid','ppidv2','lapor','lpse','sipp','simpeg','simrs','sipd','siskeudes','eoffice','eform','simda','sikd','simrs','satudata',
        // pendidikan / layanan daerah
        'siakad','elearning','pmb','perpus','library','opac','kbm',
        // admin & panel
        'admin','cpanel','panel','dashboard',
        // web aplikasi umum daerah
        'kepegawaian','bkpsdm','bkpp','bkd','bapenda','setda','diskominfo','bappeda','kependudukan','dukcapil','pajak','perizinan',
        // keamanan
        'sso','auth','login','saml',
    ];
}

/** Utility: akhiran string tanpa tergantung PHP 8 (end-with) */
if (!function_exists('ends_with_domain')) {
    function ends_with_domain(string $host, string $baseDomain): bool {
        $host = strtolower($host);
        $baseDomain = strtolower($baseDomain);
        if ($host === $baseDomain) return false; 
        $len = strlen($baseDomain) + 1;
        if (strlen($host) <= $len-1) return false;
        return substr($host, -$len) === ('.' . $baseDomain);
    }
}

/** Ambil subdomain pasif (crt.sh + BufferOver + Wayback + OTX) + mini DNS brute + cache */
function fetch_subdomains_from_crtsh(string $baseDomain, int $limit = 500): array {
    $baseDomain = strtolower(trim($baseDomain));
    if ($baseDomain === '') return [];

    // Cache 6 jam
    $cacheKey = 'subs:extended:'.$baseDomain.':'.$limit;
    $cached = cache_get($cacheKey);
    if ($cached !== null) return $cached;

    $all = [];

    // --- Sumber 1a: crt.sh (q)
    $u1 = "https://crt.sh/?q=%25." . rawurlencode($baseDomain) . "&output=json";
    $r1 = parse_crtsh_json(http_get($u1, 15, 3));
    foreach ($r1 as $row) {
        if (!isset($row['name_value'])) continue;
        foreach (preg_split('/\s+/', trim($row['name_value'])) as $nm) {
            $all[] = str_replace('*.', '', $nm);
        }
    }

   
    if (count($all) < $limit * 0.6) {
        $u1b = "https://crt.sh/?Identity=%25." . rawurlencode($baseDomain) . "&output=json";
        $r1b = parse_crtsh_json(http_get($u1b, 15, 2));
        foreach ($r1b as $row) {
            if (!isset($row['name_value'])) continue;
            foreach (preg_split('/\s+/', trim($row['name_value'])) as $nm) {
                $all[] = str_replace('*.', '', $nm);
            }
        }
    }

   
    if (count($all) < $limit) {
        $u2 = "https://dns.bufferover.run/dns?q=." . rawurlencode($baseDomain);
        $r2raw = http_get($u2, 12, 2);
        $r2 = $r2raw ? json_decode($r2raw, true) : null;
        if (is_array($r2)) {
            foreach (['FDNS_A','RDNS','FDNS_AAAA','RDNS_IPv6'] as $k) {
                if (empty($r2[$k]) || !is_array($r2[$k])) continue;
                foreach ($r2[$k] as $line) {
                    $parts = explode(',', $line);
                    foreach ($parts as $p) { $all[] = strtolower(trim($p)); }
                }
            }
        }
    }

   
    if (count($all) < $limit) {
        $wbHosts = fetch_wayback_hosts($baseDomain, $limit);
        foreach ($wbHosts as $h) { $all[] = $h; }
    }

   
    if (count($all) < $limit) {
        $otxHosts = fetch_otx_hosts($baseDomain, $limit);
        foreach ($otxHosts as $h) { $all[] = $h; }
    }

    // Normalisasi awal
    $norm = normalize_host_list($all, $baseDomain, $limit);

    
    if (count($norm) < max(10, (int)($limit * 0.05))) {
        $cands = common_idgov_candidates();
        $brute = dns_bruteforce_hosts($baseDomain, $cands, min(200, $limit));
        // gabung & re-normalisasi
        $norm = normalize_host_list(array_merge($norm, $brute), $baseDomain, $limit);
    }

    // Filter akhir: pastikan benar-benar di bawah baseDomain
    $final = [];
    foreach ($norm as $h) {
        if (ends_with_domain($h, $baseDomain)) $final[] = $h;
        if (count($final) >= $limit) break;
    }

    cache_set($cacheKey, $final);
    return $final;
}

// ========== Subdomain LIVE — FAST (curl_multi) ==========
function dns_resolves(string $host): bool {
    $host = rtrim(strtolower($host), '.');
    if (filter_var($host, FILTER_VALIDATE_IP)) return true;
    return checkdnsrr($host, 'A') || checkdnsrr($host, 'AAAA') || checkdnsrr($host, 'CNAME');
}

/**
 * Jalankan HEAD request parallel untuk banyak URL.
 * @param string[] $urls
 * @param int $timeout Per-handle timeout
 * @param int $concurrency Max handles aktif bersamaan
 * @return array Map url => ['ok'=>bool,'code'=>int|null,'final_url'=>string,'error'=>string|null]
 */
function curl_multi_head_batch(array $urls, int $timeout = 6, int $concurrency = 20): array {
    $mh = curl_multi_init();
    $results = [];
    $queue = array_values($urls);
    $active = [];
    $ua = 'IAIDU-Checker/1.1';

    // helper to add handle
    $add = function($url) use ($mh, &$active, $timeout, $ua) {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_NOBODY => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 5,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_USERAGENT => $ua
        ]);
        curl_multi_add_handle($mh, $ch);
        $active[(int)$ch] = $ch;
    };

    // prime
    while (!empty($queue) && count($active) < $concurrency) {
        $add(array_shift($queue));
    }

    do {
        $status = curl_multi_exec($mh, $running);
        if ($status > CURLM_OK) break;

        // drain completed
        while ($info = curl_multi_info_read($mh)) {
            $ch = $info['handle'];
            $url = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
            $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $err  = curl_error($ch);
            $ok   = ($info['result'] === CURLE_OK);

            $results[$url] = [
                'ok'        => $ok,
                'code'      => $code ?: null,
                'final_url' => $url,
                'error'     => $err ?: null,
            ];

            curl_multi_remove_handle($mh, $ch);
            curl_close($ch);
            unset($active[(int)$ch]);

            // add next from queue
            if (!empty($queue)) {
                $add(array_shift($queue));
            }
        }

        if ($running) {
            curl_multi_select($mh, 0.5);
        }
    } while ($running || !empty($active));

    curl_multi_close($mh);
    return $results;
}

/**
 * Versi CEPAT: cek LIVE banyak subdomain
 
 * @param string[] $hosts
 * @param int $timeout
 * @param int $concurrency
 * @return array[] daftar row: ['host','dns','live','scheme','code','note']
 */
function probe_subdomains_live_multi(array $hosts, int $timeout = 6, int $concurrency = 20): array {
    $rows = [];
    $dnsOK = [];
    foreach ($hosts as $h) {
        $h = rtrim(strtolower($h), '.');
        $hasDNS = dns_resolves($h);
        $rows[$h] = [
            'host'   => $h,
            'dns'    => $hasDNS,
            'live'   => false,
            'scheme' => null,
            'code'   => null,
            'note'   => $hasDNS ? null : 'No DNS',
        ];
        if ($hasDNS) $dnsOK[] = $h;
    }
    if (empty($dnsOK)) return array_values($rows);

    // Wave 1: HTTPS
    $httpsUrls = array_map(fn($h) => 'https://' . $h, $dnsOK);
    $httpsRes  = curl_multi_head_batch($httpsUrls, $timeout, $concurrency);

    // mark https successes
    $needHttp = [];
    foreach ($dnsOK as $h) {
        $u = 'https://' . $h;
        $r = $httpsRes[$u] ?? null;
        if ($r && ($r['code'] ?? 0) >= 200 && $r['code'] < 400) {
            $rows[$h]['live']   = true;
            $rows[$h]['scheme'] = 'https';
            $rows[$h]['code']   = $r['code'];
        } else {
            $needHttp[] = $h;
        }
    }

    // Wave 2: HTTP fallback (hanya yang belum LIVE)
    if (!empty($needHttp)) {
        $httpUrls = array_map(fn($h) => 'http://' . $h, $needHttp);
        $httpRes  = curl_multi_head_batch($httpUrls, $timeout, $concurrency);
        foreach ($needHttp as $h) {
            if ($rows[$h]['live']) continue;
            $u = 'http://' . $h;
            $r = $httpRes[$u] ?? null;
            if ($r && ($r['code'] ?? 0) >= 200 && $r['code'] < 400) {
                $rows[$h]['live']   = true;
                $rows[$h]['scheme'] = 'http';
                $rows[$h]['code']   = $r['code'];
            } else {
                $rows[$h]['code'] = $r['code'] ?? null;
                $rows[$h]['note'] = 'No HTTP(S) 2xx/3xx';
            }
        }
    }

    return array_values($rows);
}

// ========== PEMERIKSA UTAMA ==========
function check_target(string $rawUrl, array $opts = []): array {
    $result = [
        'input' => $rawUrl,
        'url' => null,
        'http_code' => null,
        'final_url' => null,
        'redirects' => 0,
        'server' => null,
        'headers' => [],
        'hsts' => false,
        'hsts_max_age' => null,
        'csp' => false,
        'xfo' => false,
        'xcto' => false,
        'cookies_total' => 0,
        'cookies_secure' => 0,
        'cookies_httponly' => 0,
        'tls_expires' => null,
        'tls_days_left' => null,
        'mixed_content_count' => 0,
        'insecure_forms' => 0,
        'robots' => 'unknown',
        'load_time_ms' => null,
        'error' => null,
        // WHOIS & Subdomain
        'domain' => null,
        'whois' => null,
        'subdomains' => [],
        // Live subdomain (opsional)
        'subdomains_live' => null,
    ];

    $url = trim($rawUrl);
    if ($url === '') { $result['error'] = 'empty target'; return $result; }
    if (!preg_match('#^https?://#i', $url)) $url = 'https://' . $url;
    $result['url'] = $url;

    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $url,
        CURLOPT_NOBODY => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 10,
        CURLOPT_HEADER => true,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT => 8,
        CURLOPT_TIMEOUT => 20,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_USERAGENT => 'IAIDU-Checker/1.1'
    ]);

    $t0 = microtime(true);
    $raw = @curl_exec($ch);
    $t1 = microtime(true);
    $result['load_time_ms'] = (int)(($t1-$t0)*1000);

    if ($raw === false) {
        $result['error'] = 'curl error: '.curl_error($ch);
        curl_close($ch);
        return $result;
    }

    $info = curl_getinfo($ch);
    $result['http_code'] = $info['http_code'] ?? null;
    $result['final_url'] = $info['url'] ?? null;
    $result['redirects'] = $info['redirect_count'] ?? 0;

    $blocks = preg_split("/\r\n\r\n/", trim($raw));
    $last = array_pop($blocks);
    $hdrLines = preg_split("/\r\n/", $last);
    $headers = [];
    foreach ($hdrLines as $i => $line) {
        if ($i === 0) { $headers[':status'] = $line; continue; }
        $p = explode(':', $line, 2);
        if (count($p) === 2) {
            $k = strtolower(trim($p[0]));
            $v = trim($p[1]);
            if (!isset($headers[$k])) $headers[$k] = $v; else $headers[$k] .= ', ' . $v;
        }
    }
    $result['headers'] = $headers;
    $result['server'] = $headers['server'] ?? ($headers['x-powered-by'] ?? null);

    $result['hsts'] = isset($headers['strict-transport-security']);
    $result['hsts_max_age'] = $result['hsts'] ? parse_hsts_max_age($headers['strict-transport-security']) : null;
    $result['csp'] = isset($headers['content-security-policy']);
    $result['xfo'] = isset($headers['x-frame-options']);
    $result['xcto'] = isset($headers['x-content-type-options']);

    // Kumpulkan Set-Cookie
    $setCookieRaw = [];
    foreach ($blocks as $block) {
        if (preg_match_all('/^Set-Cookie:\s*(.+)$/im', $block, $mc)) { foreach ($mc[1] as $cval) $setCookieRaw[] = $cval; }
    }
    if (preg_match_all('/^Set-Cookie:\s*(.+)$/im', $last, $mc2)) { foreach ($mc2[1] as $cval) $setCookieRaw[] = $cval; }
    $cookies_total = count($setCookieRaw);
    $cookies_secure = 0; $cookies_httponly = 0;
    foreach ($setCookieRaw as $c) {
        $low = strtolower($c);
        if (strpos($low,'secure') !== false) $cookies_secure++;
        if (strpos($low,'httponly') !== false) $cookies_httponly++;
    }
    $result['cookies_total'] = $cookies_total;
    $result['cookies_secure'] = $cookies_secure;
    $result['cookies_httponly'] = $cookies_httponly;

    curl_close($ch);

    // TLS expiry
    $target_for_cert = $result['final_url'] ?? $url;
    $p = parse_url($target_for_cert);
    if (isset($p['scheme']) && strtolower($p['scheme']) === 'https' && !empty($p['host'])) {
        $host = $p['host']; $port = $p['port'] ?? 443;
        $ctx = stream_context_create(["ssl"=>["capture_peer_cert"=>true, "verify_peer"=>false]]);
        $fp = @stream_socket_client("ssl://{$host}:{$port}", $errno, $errstr, 6, STREAM_CLIENT_CONNECT, $ctx);
        if ($fp !== false) {
            $params = stream_context_get_params($fp);
            if (!empty($params['options']['ssl']['peer_certificate'])) {
                $cert = $params['options']['ssl']['peer_certificate'];
                $certinfo = openssl_x509_parse($cert);
                if ($certinfo && !empty($certinfo['validTo_time_t'])) {
                    $exp = (int)$certinfo['validTo_time_t'];
                    $result['tls_expires'] = date('Y-m-d H:i:s', $exp);
                    $result['tls_days_left'] = (int)floor(($exp - time())/86400);
                }
            }
            fclose($fp);
        }
    }

    // WHOIS & Subdomain (pasif)
    $hostForEnum = $p['host'] ?? (parse_url($url, PHP_URL_HOST) ?: null);
    if ($hostForEnum) {
        $base = extract_base_domain($hostForEnum);
        $result['domain'] = $base;

        try { $result['whois'] = whois_lookup($base); }
        catch (Throwable $ex) { $result['whois'] = 'WHOIS error: ' . $ex->getMessage(); }

        try { $result['subdomains'] = fetch_subdomains_from_crtsh($base, 500); }
        catch (Throwable $ex) { $result['subdomains'] = []; }
    }

    // [FAST] Opsi cek LIVE untuk subdomain — parallel
    $result['subdomains_live'] = null;
    if (!empty($opts['check_sub_live']) && !empty($result['subdomains'])) {
        $limit       = isset($opts['sub_limit']) ? max(1, (int)$opts['sub_limit']) : 100;
        $concurrency = isset($opts['sub_concurrency']) ? max(1, (int)$opts['sub_concurrency']) : 20;
        $subset = array_slice($result['subdomains'], 0, $limit);
        $result['subdomains_live'] = probe_subdomains_live_multi($subset, 6, $concurrency);
    }

    // robots.txt
    try {
        $robots = rtrim($result['final_url'] ?? $url, '/') . '/robots.txt';
        $ch2 = curl_init();
        curl_setopt_array($ch2, [
            CURLOPT_URL => $robots,
            CURLOPT_NOBODY => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 6,
            CURLOPT_TIMEOUT => 10,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2
        ]);
        curl_exec($ch2);
        $rc = curl_getinfo($ch2, CURLINFO_HTTP_CODE);
        curl_close($ch2);
        if ($rc >= 200 && $rc < 300) $result['robots'] = 'found';
        elseif ($rc == 404) $result['robots'] = 'not found';
        else $result['robots'] = 'unknown (' . $rc . ')';
    } catch (Throwable $ex) { $result['robots'] = 'error'; }

    // Mixed content & insecure forms
    if (($result['http_code'] ?? 0) > 0 && ($result['http_code'] < 400)) {
        $ch3 = curl_init();
        curl_setopt_array($ch3, [
            CURLOPT_URL => $result['final_url'] ?? $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 6,
            CURLOPT_CONNECTTIMEOUT => 8,
            CURLOPT_TIMEOUT => 20,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_USERAGENT => 'IAIDU-Checker/1.1'
        ]);
        $body = @curl_exec($ch3);
        $ctype = curl_getinfo($ch3, CURLINFO_CONTENT_TYPE);
        curl_close($ch3);

        if ($body !== false && is_string($body) && preg_match('#text/html#i', (string)$ctype)) {
            $mixed = 0;
            if (preg_match_all('/<(?:img|script|iframe|link)\b[^>]*(?:src|href)\s*=\s*["\'](http:\/\/[^"\']+)["\']/i', $body, $mm)) {
                $mixed = count($mm[1]);
            }
            $result['mixed_content_count'] = $mixed;

            $insecure_forms = 0;
            if (preg_match_all('/<form\b[^>]*action\s*=\s*["\']([^"\']*)["\']/i', $body, $fm)) {
                foreach ($fm[1] as $act) {
                    $act = trim($act);
                    if ($act === '' || stripos($act, 'http://') === 0) $insecure_forms++;
                }
            }
            if (preg_match_all('/<form\b(?![^>]*action)[^>]*>/i', $body, $nof)) {
                $insecure_forms += count($nof[0]);
            }
            $result['insecure_forms'] = $insecure_forms;
        }
    }

    return $result;
}

// ===== CLI mode =====
$cli = (php_sapi_name() === 'cli');
$results = [];
$csv_out = null;
if ($cli) {
    $opts = getopt('', [
        'targets::','targets-file::','csv::','help::',
        'check-sub-live::','sub-limit::','sub-concurrency::'
    ]);
    if (isset($opts['help'])) {
        echo "Usage: php website_check_full_fast.php --targets=\"example.com,https://example.com\" --csv=report.csv [--check-sub-live=1] [--sub-limit=200] [--sub-concurrency=20]\n";
        exit(0);
    }
    $targets = [];
    if (!empty($opts['targets'])) {
        $parts = preg_split('/[\r\n,]+/', $opts['targets']);
        foreach ($parts as $p) { $p = trim($p); if ($p!=='') $targets[] = $p; }
    }
    if (!empty($opts['targets-file'])) {
        $f = $opts['targets-file'];
        if (is_readable($f)) {
            $content = file_get_contents($f);
            $parts = preg_split('/[\r\n,]+/', $content);
            foreach ($parts as $p) { $p=trim($p); if($p!=='') $targets[]=$p; }
        } else { fwrite(STDERR, "Targets file not readable: $f\n"); exit(2); }
    }
    if (empty($targets)) { fwrite(STDERR, "No targets given. See --help\n"); exit(2);}

    $csv_out = $opts['csv'] ?? null;
    $checkSub = !empty($opts['check-sub-live']);
    $subLimit = isset($opts['sub-limit']) ? (int)$opts['sub-limit'] : 200;
    $subConc  = isset($opts['sub-concurrency']) ? (int)$opts['sub-concurrency'] : 20;

    foreach ($targets as $t) {
        $r = check_target($t, [
            'check_sub_live'   => $checkSub,
            'sub_limit'        => $subLimit,
            'sub_concurrency'  => $subConc,
        ]);
        $results[] = $r;
        echo "[".now_iso()."] {$r['input']} => ".($r['http_code']??'ERR')."\n";
    }
    if ($csv_out) {
        $fh = fopen($csv_out, 'w');
        if ($fh) {
            fputcsv($fh, ['input','url','http_code','final_url','redirects','server','hsts','hsts_max_age','csp','xfo','xcto','cookies_total','cookies_secure','cookies_httponly','tls_expires','tls_days_left','mixed_content_count','insecure_forms','robots','load_time_ms','error']);
            foreach ($results as $r) {
                fputcsv($fh, [
                    $r['input'],$r['url'],$r['http_code'],$r['final_url'],$r['redirects'],$r['server'],
                    $r['hsts']?'yes':'no', $r['hsts_max_age']??'', $r['csp']?'yes':'no', $r['xfo']?'yes':'no', $r['xcto']?'yes':'no',
                    $r['cookies_total'],$r['cookies_secure'],$r['cookies_httponly'],
                    $r['tls_expires'],$r['tls_days_left'],$r['mixed_content_count'],$r['insecure_forms'],
                    $r['robots'],$r['load_time_ms'],$r['error']
                ]);
            }
            fclose($fh);
            echo "CSV written to $csv_out\n";
        } else { fwrite(STDERR, "Unable to write CSV to $csv_out\n"); }
    }
    exit(0);
}

// ===== Web UI mode =====
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $raw = $_POST['targets'] ?? '';
    $targets = [];
    $parts = preg_split('/[\r\n,]+/', $raw);
    foreach ($parts as $p) { $p = trim($p); if ($p !== '') $targets[] = $p; }

    $check_sub_live = !empty($_POST['check_sub_live']);
    $sub_limit      = isset($_POST['sub_limit']) ? (int)$_POST['sub_limit'] : 200;
    $sub_conc       = isset($_POST['sub_concurrency']) ? (int)$_POST['sub_concurrency'] : 20;


    foreach ($targets as $t) {
        $results[] = check_target($t, [
            'check_sub_live'   => $check_sub_live,
            'sub_limit'        => $sub_limit,
            'sub_concurrency'  => $sub_conc,
        ]);
    }

    if (isset($_POST['export_csv']) && !empty($results)) {
        $fname = 'website-check-'.date('Ymd-His').'.csv';
        header('Content-Type: text/csv; charset=utf-8');
        header('Content-Disposition: attachment; filename="'.$fname.'"');
        $out = fopen('php://output', 'w');
        fputcsv($out, ['input','url','http_code','final_url','redirects','server','hsts','hsts_max_age','csp','xfo','xcto','cookies_total','cookies_secure','cookies_httponly','tls_expires','tls_days_left','mixed_content_count','insecure_forms','robots','load_time_ms','error']);
        foreach ($results as $r) {
            fputcsv($out, [
                $r['input'],$r['url'],$r['http_code'],$r['final_url'],$r['redirects'],$r['server'],
                $r['hsts']?'yes':'no', $r['hsts_max_age']??'', $r['csp']?'yes':'no', $r['xfo']?'yes':'no', $r['xcto']?'yes':'no',
                $r['cookies_total'],$r['cookies_secure'],$r['cookies_httponly'],
                $r['tls_expires'],$r['tls_days_left'],$r['mixed_content_count'],$r['insecure_forms'],
                $r['robots'],$r['load_time_ms'],$r['error']
            ]);
        }
        fclose($out);
        exit;
    }
}

// ===== Rekomendasi (Solusi) aggregator =====
function build_recommendations(array $results): array {
    $agg = [
        'need_hsts' => false,
        'need_csp' => false,
        'need_xfo' => false,
        'need_xcto' => false,
        'tls_soon' => [],
        'mixed' => [],
        'forms' => [],
    ];
    foreach ($results as $r) {
        if (!$r) continue;
        if (!$r['hsts']) $agg['need_hsts'] = true;
        if (!$r['csp']) $agg['need_csp'] = true;
        if (!$r['xfo']) $agg['need_xfo'] = true;
        if (!$r['xcto']) $agg['need_xcto'] = true;
        if (isset($r['tls_days_left']) && $r['tls_days_left'] !== null && $r['tls_days_left'] <= 30) $agg['tls_soon'][] = [$r['input'],$r['tls_days_left']];
        if (($r['mixed_content_count'] ?? 0) > 0) $agg['mixed'][] = [$r['input'],$r['mixed_content_count']];
        if (($r['insecure_forms'] ?? 0) > 0) $agg['forms'][] = [$r['input'],$r['insecure_forms']];
    }
    return $agg;
}

$agg = build_recommendations($results ?? []);

?>
<!doctype html>
<html lang="id">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Website Checker</title>
<style>
body{font-family:Inter,system-ui,Arial;background:#f8fafc;color:#0f172a;padding:18px}
.container{max-width:1100px;margin:0 auto}
h1{margin:0 0 8px}
textarea{width:100%;height:120px;padding:10px;border-radius:8px;border:1px solid #cbd5e1;resize:vertical}
button, input[type="submit"]{padding:10px 14px;border-radius:8px;border:none;background:#0369a1;color:#fff;cursor:pointer}
button.secondary{background:#334155}
table{width:100%;border-collapse:collapse;margin-top:18px}
th,td{padding:8px;border:1px solid #e6eef8;text-align:left;font-size:13px}
.bad{display:inline-block;padding:4px 8px;border-radius:999px;background:#fee2e2;color:#991b1b;font-weight:600}
.good{display:inline-block;padding:4px 8px;border-radius:999px;background:#dcfce7;color:#065f46;font-weight:600}
.muted{color:#64748b}
small{color:#475569}
pre{background:#fff;padding:8px;border-radius:6px;border:1px solid #e6eef8;overflow:auto}
.form-row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
@media (max-width:700px){ .form-row{flex-direction:column;align-items:stretch} }
.card{background:#ffffff;border:1px solid #e6eef8;border-radius:10px;padding:12px;margin-top:14px}
.card h3{margin:0 0 8px}
.codecols{display:grid;grid-template-columns:1fr 1fr;gap:12px}
@media (max-width:900px){.codecols{grid-template-columns:1fr}}
.tag{display:inline-block;padding:2px 8px;border-radius:999px;background:#eef2ff;color:#3730a3;margin-right:6px;font-size:12px}
input[type="number"]{border:1px solid #cbd5e1;border-radius:8px}
</style>
</head>
<body>
<div class="container">
  <h1>Website Checker</h1>
  <p class="muted">Masukkan target (URL/domain) dipisah koma atau newline. Jika tanpa scheme, diasumsikan <code>https://</code>.</p>

  <form method="post" autocomplete="off">
    <textarea name="targets" placeholder="contoh: example.com&#10;https://subdomain.example.com"><?php echo isset($_POST['targets'])? e($_POST['targets']) : '' ?></textarea>

    <div class="form-row" style="margin-top:8px">
      <label style="display:flex;align-items:center;gap:8px">
        <input type="checkbox" name="check_sub_live" value="1" <?php echo !empty($_POST['check_sub_live'])?'checked':''; ?>>
        <span>Cek status <b>LIVE</b> subdomain (DNS + HTTP/HTTPS)</span>
      </label>
      <label class="muted" style="display:flex;align-items:center;gap:8px">
        Batas cek:
        <input type="number" min="1" max="2000" name="sub_limit" value="<?php echo e($_POST['sub_limit'] ?? '200'); ?>" style="width:90px;padding:6px;">
      </label>
      <label class="muted" style="display:flex;align-items:center;gap:8px">
        Concurrency:
        <input type="number" min="1" max="100" name="sub_concurrency" value="<?php echo e($_POST['sub_concurrency'] ?? '20'); ?>" style="width:90px;padding:6px;">
      </label>

      <div style="margin-left:auto;color:#475569;font-size:13px">Checked : <?php echo e(date('d-m-Y')) ?></div>
    </div>

    <div class="form-row" style="margin-top:8px">
      <input type="submit" value="Scan">
      <button class="secondary" type="submit" name="export_csv" value="1">Export CSV</button>
    </div>
  </form>
<div id="loadingOverlay" style="display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(255,255,255,0.9);z-index:9999;/* jangan set display:flex di sini */">
  <div style="width:100%;height:100%;display:flex;flex-direction:column;justify-content:center;align-items:center;font-family:Inter,sans-serif;color:#0f172a;">
    <div style="width:60%;max-width:400px;background:#e2e8f0;border-radius:999px;overflow:hidden;margin-bottom:16px;">
      <div id="loadingBar" style="height:20px;width:0;background:#0369a1;transition:width 0.3s;"></div>
    </div>
    <div id="loadingText" style="font-weight:600;">Memulai scan...</div>
  </div>
</div>

<?php if (!empty($results)): ?>
  <h3 style="margin-top:18px">WHOIS & Subdomain</h3>
  <?php foreach ($results as $r): ?>
    <div class="card">
      <h3 style="margin-bottom:6px"><?php echo e($r['input']) ?> <?php if(!empty($r['domain'])): ?><span class="muted">— base: <?php echo e($r['domain']) ?></span><?php endif; ?></h3>

      <details open>
        <summary><b>WHOIS</b></summary>
        <pre><?php echo e(is_string($r['whois'] ?? '') ? $r['whois'] : var_export($r['whois'], true)); ?></pre>
      </details>

      <details style="margin-top:6px">
        <summary><b>Subdomain</b> — <?php echo isset($r['subdomains']) ? count($r['subdomains']) : 0; ?> ditemukan</summary>
        <?php
        if (!empty($r['subdomains'])) {
            // indekskan hasil live agar lookup cepat
            $liveIndex = [];
            if (isset($r['subdomains_live']) && is_array($r['subdomains_live'])) {
                foreach ($r['subdomains_live'] as $row) {
                    if (!empty($row['host'])) $liveIndex[strtolower($row['host'])] = $row;
                }
            }

            if (!empty($liveIndex)) {
                echo '<table style="margin-top:8px">';
                echo '<thead><tr><th>Subdomain</th><th>DNS</th><th>Status</th><th>Kode</th><th>Skema</th><th>Catatan</th></tr></thead><tbody>';
                foreach ($r['subdomains'] as $sd) {
                    $key = strtolower($sd);
                    $row = $liveIndex[$key] ?? null;
                    if ($row) {
                        if (!empty($row['live']))      $statusHtml = '<span class="good">LIVE</span>';
                        elseif (!empty($row['dns']))   $statusHtml = '<span class="muted">DNS only</span>';
                        else                           $statusHtml = '<span class="bad">DOWN</span>';
                    } else {
                        $statusHtml = '<span class="muted">-</span>'; // di luar limit/tdk dicek
                    }
                    echo '<tr>';
                    echo '<td style="max-width:300px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">'.e($sd).'</td>';
                    echo '<td>'.($row ? ($row['dns'] ? '<span class="good">ya</span>' : '<span class="bad">tidak</span>') : '<span class="muted">-</span>').'</td>';
                    echo '<td>'.$statusHtml.'</td>';
                    echo '<td>'.($row && $row['code']!==null ? e((string)$row['code']) : '-').'</td>';
                    echo '<td>'.($row && $row['scheme'] ? e($row['scheme']) : '-').'</td>';
                    echo '<td class="muted">'.($row && !empty($row['note']) ? e($row['note']) : '-').'</td>';
                    echo '</tr>';
                }
                echo '</tbody></table>';
                echo '<small class="muted">Kriteria LIVE: DNS resolve dan respon HTTP/HTTPS berstatus 2xx/3xx.</small>';
            } else {
                echo '<pre>'.e(implode("\n", $r['subdomains'])).'</pre>';
                echo '<p class="muted">Centang opsi <b>“Cek status LIVE subdomain”</b> untuk melihat status akses.</p>';
            }
        } else {
            echo '<p class="muted">Tidak ada data subdomain atau layanan CT tidak mengembalikan hasil.</p>';
        }
        ?>
      </details>

      <?php if (isset($r['subdomains_live'])):
          $rows = $r['subdomains_live'] ?? [];
          $liveCount = 0; foreach ($rows as $row) { if (!empty($row['live'])) $liveCount++; }
      ?>
        <details style="margin-top:6px" open>
          <summary><b>Ringkas LIVE</b> — <?php echo e((string)$liveCount) ?> / <?php echo e((string)count($rows)) ?> LIVE</summary>
          <?php if ($rows): ?>
            <table style="margin-top:8px">
              <thead>
                <tr>
                  <th>Subdomain</th>
                  <th>DNS</th>
                  <th>Status</th>
                  <th>Kode</th>
                  <th>Skema</th>
                  <th>Catatan</th>
                </tr>
              </thead>
              <tbody>
                <?php foreach ($rows as $row): ?>
                  <tr>
                    <td style="max-width:300px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis"><?php echo e($row['host']) ?></td>
                    <td><?php echo $row['dns'] ? '<span class="good">ya</span>' : '<span class="bad">tidak</span>'; ?></td>
                    <td>
                      <?php
                        if ($row['live'])      echo '<span class="good">LIVE</span>';
                        elseif ($row['dns'])   echo '<span class="muted">DNS only</span>';
                        else                   echo '<span class="bad">DOWN</span>';
                      ?>
                    </td>
                    <td><?php echo e($row['code'] !== null ? (string)$row['code'] : '-') ?></td>
                    <td><?php echo e($row['scheme'] ?? '-') ?></td>
                    <td class="muted"><?php echo e($row['note'] ?? '-') ?></td>
                  </tr>
                <?php endforeach; ?>
              </tbody>
            </table>
          <?php else: ?>
            <p class="muted">Tidak ada subdomain yang dicek.</p>
          <?php endif; ?>
        </details>
      <?php endif; ?>
    </div>
  <?php endforeach; ?>

  <h2 style="margin-top:18px">Hasil</h2>
  <table>
    <thead>
      <tr>
        <th>Input</th><th>HTTP</th><th>Final URL</th><th>Server</th><th>Security</th><th>TLS expires</th><th>robots</th><th>Mixed</th><th>Forms</th><th>Load(ms)</th>
      </tr>
    </thead>
    <tbody>
    <?php foreach ($results as $r): ?>
      <tr>
        <td><?php echo e($r['input']) ?><?php if($r['error']): ?><div class="bad"><?php echo e($r['error']) ?></div><?php endif; ?></td>
        <td><?php echo e($r['http_code'] ?? '-') ?> (r:<?php echo e($r['redirects']) ?>)</td>
        <td style="max-width:220px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis"><?php echo e($r['final_url'] ?? '-') ?></td>
        <td><?php echo e($r['server'] ?? '-') ?></td>
        <td>
          HSTS: <?php echo $r['hsts']? '<span class="good">yes</span>' : '<span class="muted">no</span>' ?>
          <?php if($r['hsts'] && $r['hsts_max_age']!==null): ?><br><small>max-age=<?php echo e($r['hsts_max_age']) ?></small><?php endif; ?><br>
          CSP: <?php echo $r['csp']? '<span class="good">yes</span>' : '<span class="muted">no</span>' ?><br>
          XFO: <?php echo $r['xfo']? '<span class="good">yes</span>' : '<span class="muted">no</span>' ?><br>
          XCTO: <?php echo $r['xcto']? '<span class="good">yes</span>' : '<span class="muted">no</span>' ?>
        </td>
        <td><?php echo e($r['tls_expires'] ?? '-') ?> <?php echo isset($r['tls_days_left']) ? '('.e($r['tls_days_left']).' hari)' : '' ?></td>
        <td><?php echo e($r['robots']) ?></td>
        <td><?php echo e($r['mixed_content_count']) ?></td>
        <td><?php echo e($r['insecure_forms']) ?></td>
        <td><?php echo e($r['load_time_ms']) ?></td>
      </tr>
    <?php endforeach; ?>
    </tbody>
  </table>

  <!-- ============ SOLUSI / REKOMENDASI ============ -->
  <?php
    $showAllGood = !$agg['need_hsts'] && !$agg['need_csp'] && !$agg['need_xfo'] && !$agg['need_xcto'] &&
                   empty($agg['tls_soon']) && empty($agg['mixed']) && empty($agg['forms']);
  ?>
  <div class="card">
    <h3>Solusi & Rekomendasi</h3>
    <?php if ($agg['need_hsts']): ?><span class="tag">HSTS</span><?php endif; ?>
    <?php if ($agg['need_csp']): ?><span class="tag">CSP</span><?php endif; ?>
    <?php if ($agg['need_xfo']): ?><span class="tag">X-Frame-Options</span><?php endif; ?>
    <?php if ($agg['need_xcto']): ?><span class="tag">X-Content-Type-Options</span><?php endif; ?>
    <?php if (!empty($agg['tls_soon'])): ?><span class="tag">TLS Expiring ≤ 30 hari</span><?php endif; ?>
    <?php if (!empty($agg['mixed'])): ?><span class="tag">Mixed Content</span><?php endif; ?>
    <?php if (!empty($agg['forms'])): ?><span class="tag">Insecure Forms</span><?php endif; ?>

    <?php if ($agg['need_hsts']): ?>
      <details open>
        <summary><b>Aktifkan HTTP Strict Transport Security (HSTS)</b></summary>
        <div class="codecols">
<pre><code># Apache (.htaccess)
&lt;IfModule mod_headers.c&gt;
  Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
&lt;/IfModule&gt;
</code></pre>
<pre><code># Nginx (server block)
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
</code></pre>
        </div>
      </details>
    <?php endif; ?>

    <?php if ($agg['need_csp']): ?>
      <details>
        <summary><b>Tambahkan Content-Security-Policy (CSP)</b></summary>
        <div class="codecols">
<pre><code># Apache
&lt;IfModule mod_headers.c&gt;
  Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'"
&lt;/IfModule&gt;
</code></pre>
<pre><code># Nginx
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'";
</code></pre>
        </div>
      </details>
    <?php endif; ?>

    <?php if ($agg['need_xfo']): ?>
      <details>
        <summary><b>Aktifkan X-Frame-Options (anti-clickjacking)</b></summary>
        <div class="codecols">
<pre><code># Apache
&lt;IfModule mod_headers.c&gt;
  Header always set X-Frame-Options "SAMEORIGIN"
&lt;/IfModule&gt;
</code></pre>
<pre><code># Nginx
add_header X-Frame-Options "SAMEORIGIN";
</code></pre>
        </div>
      </details>
    <?php endif; ?>

    <?php if ($agg['need_xcto']): ?>
      <details>
        <summary><b>Aktifkan X-Content-Type-Options (nosniff)</b></summary>
        <div class="codecols">
<pre><code># Apache
&lt;IfModule mod_headers.c&gt;
  Header always set X-Content-Type-Options "nosniff"
&lt;/IfModule&gt;
</code></pre>
<pre><code># Nginx
add_header X-Content-Type-Options "nosniff";
</code></pre>
        </div>
      </details>
    <?php endif; ?>

    <?php if (!empty($agg['tls_soon'])): ?>
      <details open>
        <summary><b>Perbarui Sertifikat TLS yang Hampir Kedaluwarsa</b></summary>
        <ul>
          <?php foreach ($agg['tls_soon'] as $pair): list($host,$days) = $pair; ?>
            <li><?php echo e($host) ?> — sisa <?php echo e((string)$days) ?> hari</li>
          <?php endforeach; ?>
        </ul>
      </details>
    <?php endif; ?>

    <?php if (!empty($agg['mixed'])): ?>
      <details open>
        <summary><b>Perbaiki Mixed Content</b></summary>
        <ul>
          <?php foreach ($agg['mixed'] as $pair): list($host,$cnt)=$pair; ?>
            <li><?php echo e($host) ?> — <?php echo e((string)$cnt) ?> resource <code>http://</code> pada halaman HTTPS</li>
          <?php endforeach; ?>
        </ul>
      </details>
    <?php endif; ?>

    <?php if (!empty($agg['forms'])): ?>
      <details open>
        <summary><b>Amankan Form</b></summary>
        <ul>
          <?php foreach ($agg['forms'] as $pair): list($host,$cnt)=$pair; ?>
            <li><?php echo e($host) ?> — <?php echo e((string)$cnt) ?> form tanpa <code>action</code> atau mengarah ke <code>http://</code></li>
          <?php endforeach; ?>
        </ul>
      </details>
    <?php endif; ?>

    <?php if ($showAllGood): ?>
      <p><b>Semua aman.</b> Tidak ada rekomendasi prioritas saat ini.</p>
    <?php endif; ?>
  </div>

  <h3 style="margin-top:12px">Headers</h3>
  <?php foreach ($results as $r): ?>
    <details style="margin-bottom:6px">
      <summary><?php echo e($r['input']) ?> — headers & extras</summary>
      <pre><?php echo e(var_export($r, true)); ?></pre>
    </details>
  <?php endforeach; ?>
<?php endif; ?>

  <hr style="margin-top:18px">
  <small class="muted">Crafted by : <code>MuftiMedia IT Solutions</code></small>
  <br><small class="muted">Cron (03:00): <code>0 3 * * * /usr/bin/php /path/website_check_full_fast.php --targets-file=/path/targets.txt --csv=/path/reports/report-$(date +\%F).csv --check-sub-live=1 --sub-limit=400 --sub-concurrency=20</code></small>
</div>
<script>
(function(){
  const form = document.querySelector('form');
  const overlay = document.getElementById('loadingOverlay');
  const bar = document.getElementById('loadingBar');
  const text = document.getElementById('loadingText');
  let interval = null, progress = 0;

  function showOverlay(){
    if (!overlay) return;
    overlay.style.display = 'flex';   // <- muncul sebagai flex
    progress = 0;
    bar.style.width = '0%';
    text.textContent = 'Memulai scan...';
    // simulasi naik sampai 95%
    interval = setInterval(() => {
      progress += Math.random() * 10;
      if (progress > 95) progress = 95;
      bar.style.width = progress + '%';
      text.textContent = 'Memindai... ' + Math.round(progress) + '%';
    }, 300);
  }

  function hideOverlay(){
    if (!overlay) return;
    overlay.style.display = 'none';
    if (interval) { clearInterval(interval); interval = null; }
  }

  // Tampilkan saat submit (Scan / Export CSV)
  if (form) {
    form.addEventListener('submit', function(){
      showOverlay();
    });
  }

  // Pastikan overlay hilang kalau halaman selesai render (mis. setelah reload)
  window.addEventListener('load', hideOverlay);

  // Antisipasi bfcache (navigasi back/forward bisa menampilkan state lama)
  window.addEventListener('pageshow', function(e){
    if (e.persisted) hideOverlay();
  });

  // Jika ada error JS, jangan biarkan overlay nyangkut
  window.addEventListener('error', hideOverlay);
})();
</script>

</body>
</html>
