// KavachRecon — module registry (execution order matters)
import { dnsModules } from './dns.js';
import { passiveModules } from './passive.js';
import { activeModules } from './active.js';
import { webModules } from './web.js';

export const MODULES = [
  ...dnsModules,       // dns_enum, email_security, subdomain_brute, dns_analysis
  ...passiveModules,   // ct_logs, whois_intel, asn_mapping, historical_dns, url_archive
  ...activeModules,    // host_discovery, port_scan, http_probe, tls_analysis
  ...webModules,       // tech_fingerprint, waf_cdn, security_posture, robots_sitemap, endpoint_discovery, js_intel, cloud_intel, screenshot
];
