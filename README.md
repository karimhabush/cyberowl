
 <div id='top'></div>

# CyberOwl AI

 
 Aggregates security advisories from 10 international CERTs daily and provides an AI skill that cross-references alerts against your project's tech stack.
 
 **Website:** [cyberowlai.com](https://cyberowlai.com)
 

## AI Skill

 Add the CyberOwl AI skill to your IDE to check if recent alerts affect your project:
**Claude Code:**
```bash
mkdir -p .claude/skills/cyberowlai && curl -o .claude/skills/cyberowlai/SKILL.md https://cyberowlai.com/skill/SKILL.md
```

**Cursor:**
```bash
mkdir -p .cursor/rules && curl -o .cursor/rules/cyberowlai.md https://cyberowlai.com/skill/SKILL.md
```

 
 ---
 
 > Last updated 23/04/2026 11:21:30 UTC
 
 |CyberOwl AI Sources|Description|
 |---|---|
 |[US-CERT](#us-cert-arrow_heading_up)|United States Computer Emergency and Readiness Team.|
 |[MA-CERT](#ma-cert-arrow_heading_up)|Moroccan Computer Emergency Response Team.|
 |[CERT-FR](#cert-fr-arrow_heading_up)|The French national government Computer Security Incident Response Team.|
 |[IBM X-Force Exchange](#ibmcloud-arrow_heading_up)|A cloud-based threat intelligence platform that allows to consume, share and act on threat intelligence.|
 |[ZeroDayInitiative](#zerodayinitiative-arrow_heading_up)|An international software vulnerability initiative that was started in 2005 by TippingPoint.|
 |[OBS Vigilance](#obs-vigilance-arrow_heading_up)|Vigilance is an initiative created by OBS (Orange Business Services) since 1999 to watch public vulnerabilities and then offer security fixes, a database and tools to remediate them.|
 |[VulDB](#vuldb-arrow_heading_up)|Number one vulnerability database documenting and explaining security vulnerabilities, threats, and exploits since 1970.|
 |[HK-CERT](#hk-cert-arrow_heading_up)|Hong Kong Computer Emergency Response Team Coordination Centre.|
 |[CA-CCS](#ca-ccs-arrow_heading_up)|Canadian Centre for Cyber Security.|
 |[EU-CERT](#eu-cert-arrow_heading_up)|European Union Agency for Cybersecurity.|

# US-CERT

 |Title|Description|Date|
 |---|---|---|
 |[CISA Adds One Known Exploited Vulnerability to Catalog](https://www.cisa.gov/news-events/alerts/2026/04/22/cisa-adds-one-known-exploited-vulnerability-catalog)|Visit link for details.|Apr 22, 2026|
 |[CISA Adds Eight Known Exploited Vulnerabilities to Catalog](https://www.cisa.gov/news-events/alerts/2026/04/20/cisa-adds-eight-known-exploited-vulnerabilities-catalog)|Visit link for details.|Apr 20, 2026|
 |[​​Supply Chain Compromise Impacts Axios Node Package Manager​ ](https://www.cisa.gov/news-events/alerts/2026/04/20/supply-chain-compromise-impacts-axios-node-package-manager)|Visit link for details.|Apr 20, 2026|
 |[CISA Adds One Known Exploited Vulnerability to Catalog](https://www.cisa.gov/news-events/alerts/2026/04/16/cisa-adds-one-known-exploited-vulnerability-catalog)|Visit link for details.|Apr 16, 2026|
 |[CISA Adds Two Known Exploited Vulnerabilities to Catalog](https://www.cisa.gov/news-events/alerts/2026/04/14/cisa-adds-two-known-exploited-vulnerabilities-catalog)|Visit link for details.|Apr 14, 2026|
 |[CISA Adds Seven Known Exploited Vulnerabilities to Catalog](https://www.cisa.gov/news-events/alerts/2026/04/13/cisa-adds-seven-known-exploited-vulnerabilities-catalog)|Visit link for details.|Apr 13, 2026|
 |[CISA Adds One Known Exploited Vulnerability to Catalog](https://www.cisa.gov/news-events/alerts/2026/04/08/cisa-adds-one-known-exploited-vulnerability-catalog)|Visit link for details.|Apr 08, 2026|
 |[CISA Adds One Known Exploited Vulnerability to Catalog](https://www.cisa.gov/news-events/alerts/2026/04/06/cisa-adds-one-known-exploited-vulnerability-catalog)|Visit link for details.|Apr 06, 2026|
 |[CISA Adds One Known Exploited Vulnerability to Catalog](https://www.cisa.gov/news-events/alerts/2026/04/02/cisa-adds-one-known-exploited-vulnerability-catalog)|Visit link for details.|Apr 02, 2026|
 |[CISA Adds One Known Exploited Vulnerability to Catalog](https://www.cisa.gov/news-events/alerts/2026/04/01/cisa-adds-one-known-exploited-vulnerability-catalog)|Visit link for details.|Apr 01, 2026|
 

# CERT-FR

 |Title|Description|Date|
 |---|---|---|
 |[Multiples vulnérabilités dans les produits Mozilla](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0480/)|De multiples vulnérabilités ont été découvertes dans les produits Mozilla. Certaines d'entre elles permettent à un attaquant de provoquer une exécution de code arbitraire à distance, une élévation de privilèges et un déni de service à distance.|Publié le 22 avril 2026|
 |[Multiples vulnérabilités dans les produits Atlassian](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0479/)|De multiples vulnérabilités ont été découvertes dans les produits Atlassian. Certaines d'entre elles permettent à un attaquant de provoquer une exécution de code arbitraire à distance, un déni de service à distance et une atteinte à la confidentialité des données.|Publié le 22 avril 2026|
 |[Vulnérabilité dans Microsoft .Net](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0478/)|Une vulnérabilité a été découverte dans Microsoft .Net. Elle permet à un attaquant de provoquer une élévation de privilèges.|Publié le 22 avril 2026|
 |[Multiples vulnérabilités dans les produits Spring](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0477/)|De multiples vulnérabilités ont été découvertes dans les produits Spring. Certaines d'entre elles permettent à un attaquant de provoquer une élévation de privilèges, une falsification de requêtes côté serveur (SSRF) et une injection de code indirecte à distance (XSS).|Publié le 22 avril 2026|
 |[Multiples vulnérabilités dans les produits NetApp](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0476/)|De multiples vulnérabilités ont été découvertes dans les produits NetApp. Elles permettent à un attaquant de provoquer une atteinte à la confidentialité des données et un déni de service.|Publié le 22 avril 2026|
 |[Multiples vulnérabilités dans GitLab](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0475/)|De multiples vulnérabilités ont été découvertes dans GitLab. Certaines d'entre elles permettent à un attaquant de provoquer une atteinte à la confidentialité des données, une injection de code indirecte à distance (XSS) et une injection de requêtes illégitimes par rebond (CSRF).|Publié le 22 avril 2026|
 |[Vulnérabilité dans Python](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0474/)|Une vulnérabilité a été découverte dans Python. Elle permet à un attaquant de provoquer un problème de sécurité non spécifié par l'éditeur.|Publié le 22 avril 2026|
 |[Multiples vulnérabilités dans Oracle Weblogic](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0473/)|De multiples vulnérabilités ont été découvertes dans Oracle Weblogic. Certaines d'entre elles permettent à un attaquant de provoquer une exécution de code arbitraire à distance, un déni de service à distance et une atteinte à la confidentialité des données.|Publié le 22 avril 2026|
 |[Multiples vulnérabilités dans Oracle Virtualization](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0472/)|De multiples vulnérabilités ont été découvertes dans Oracle Virtualization. Certaines d'entre elles permettent à un attaquant de provoquer une exécution de code arbitraire à distance, un déni de service à distance et une atteinte à la confidentialité des données.|Publié le 22 avril 2026|
 |[Multiples vulnérabilités dans Oracle Systems](https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0471/)|De multiples vulnérabilités ont été découvertes dans Oracle Systems. Elles permettent à un attaquant de provoquer une exécution de code arbitraire à distance et un déni de service.|Publié le 22 avril 2026|
 

# OBS-Vigilance

 |Title|Description|Date|
 |---|---|---|
 |[<a href="https://vigilance.fr/vulnerability/Redis-write-access-via-Linefeed-Error-Reply-49765" class="noirorange"><b>Redis</b>: write access via Linefeed Error Reply</a>](https://vigilance.fr/vulnerability/Redis-write-access-via-Linefeed-Error-Reply-49765)|An attacker can bypass access restrictions of Redis, via Linefeed Error Reply, in order to alter data...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/Chrome-Edge-Opera-memory-corruption-via-Type-Confusion-47785" class="noirorange"><b>Chrome  Edge  Opera</b>: memory corruption via Type Confusion</a>](https://vigilance.fr/vulnerability/Chrome-Edge-Opera-memory-corruption-via-Type-Confusion-47785)|An attacker can trigger a memory corruption of Chrome  Edge  Opera, via Type Confusion, in order to trigger a denial of service, and possibly to run code...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/ModSecurity-Core-Rule-Set-ingress-filtering-bypass-via-Multiple-Content-Type-Request-Headers-49763" class="noirorange"><b>ModSecurity Core Rule Set</b>: ingress filtering bypass via Multiple Content-Type Request Headers</a>](https://vigilance.fr/vulnerability/ModSecurity-Core-Rule-Set-ingress-filtering-bypass-via-Multiple-Content-Type-Request-Headers-49763)|An attacker can bypass filtering rules of ModSecurity Core Rule Set, via Multiple Content-Type Request Headers, in order to send malicious data...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/ImageMagick-multiple-vulnerabilities-dated-22-02-2026-49764" class="noirorange"><b>ImageMagick</b>: multiple vulnerabilities dated 22/02/2026</a>](https://vigilance.fr/vulnerability/ImageMagick-multiple-vulnerabilities-dated-22-02-2026-49764)|An attacker can use several vulnerabilities of ImageMagick, dated 22/02/2026...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/Fulcio-Server-Side-Request-Forgery-via-MetaIssuer-URL-Validation-49760" class="noirorange"><b>Fulcio</b>: Server-Side Request Forgery via MetaIssuer URL Validation</a>](https://vigilance.fr/vulnerability/Fulcio-Server-Side-Request-Forgery-via-MetaIssuer-URL-Validation-49760)|An attacker can trigger a Server-Side Request Forgery of Fulcio, via MetaIssuer URL Validation, in order to force the server to send queries...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/MuPDF-double-free-via-fz-fill-pixmap-from-display-list-49762" class="noirorange"><b>MuPDF</b>: double free via fz_fill_pixmap_from_display_list()</a>](https://vigilance.fr/vulnerability/MuPDF-double-free-via-fz-fill-pixmap-from-display-list-49762)|An attacker can force a double memory free of MuPDF, via fz_fill_pixmap_from_|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/sigstore-file-write-via-TUF-Client-49761" class="noirorange"><b>sigstore</b>: file write via TUF Client</a>](https://vigilance.fr/vulnerability/sigstore-file-write-via-TUF-Client-49761)|An attacker can bypass access restrictions of sigstore, via TUF Client, in order to alter files...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/Mozilla-Firefox-Thunderbird-multiple-vulnerabilities-dated-22-07-2025-47779" class="noirorange"><b>Mozilla Firefox  Thunderbird</b>: multiple vulnerabilities dated 22/07/2025</a>](https://vigilance.fr/vulnerability/Mozilla-Firefox-Thunderbird-multiple-vulnerabilities-dated-22-07-2025-47779)|An attacker can use several vulnerabilities of Mozilla Firefox  Thunderbird, dated 22/07/2025...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/PowerDNS-Recursor-Cache-poisoning-via-EDNS-Client-Subnet-47761" class="noirorange"><b>PowerDNS Recursor</b>: Cache poisoning via EDNS Client Subnet</a>](https://vigilance.fr/vulnerability/PowerDNS-Recursor-Cache-poisoning-via-EDNS-Client-Subnet-47761)|An attacker can poison the cache of PowerDNS Recursor, via EDNS Client Subnet, in order to hijack trafic...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/Microsoft-Office-SharePoint-Server-privilege-escalation-dated-21-07-2025-47756" class="noirorange"><b>Microsoft Office SharePoint Server</b>: privilege escalation dated 21/07/2025</a>](https://vigilance.fr/vulnerability/Microsoft-Office-SharePoint-Server-privilege-escalation-dated-21-07-2025-47756)|An attacker can bypass restrictions of Microsoft Office SharePoint Server, dated 21/07/2025, in order to escalate his privileges...|Visit link for details|
 

# VulDB

 |Title|Description|Date|
 |---|---|---|
 |[CVE-2026-41040  GROWI redos (EUVD-2026-25199)](https://vuldb.com/vuln/359127)|A vulnerability described as problematic has been identified in GROWI. This impacts an unknown function. Such manipulation leads to inefficient regular expression complexity.This vulnerability is do|Thu, 23 Apr 2026 11:42:13 +0200|
 |[CVE-2025-10549  EfficientLab Controlio up to 1.3.94 uncontrolled search path (EUVD-2025-209559)](https://vuldb.com/vuln/359126)|A vulnerability marked as problematic has been reported in EfficientLab Controlio up to 1.3.94. This affects an unknown function. This manipulation causes uncontrolled search path.This vulnerability|Thu, 23 Apr 2026 11:41:44 +0200|
 |[CVE-2026-41564  MIK CryptX up to 0.087 on Perl X25519 X25519 Modules prng seed (GHSA-24c2-gp6c-24c6 / EUVD-2026-25201)](https://vuldb.com/vuln/359125)|A vulnerability labeled as problematic has been found in MIK CryptX up to 0.087 on Perl. The impacted element is the function Crypt::PK::RSA/Crypt::PK::DSA/Crypt::PK::DH/Crypt::PK::ECC/Crypt::PK::Ed25|Thu, 23 Apr 2026 11:41:18 +0200|
 |[CVE-2026-4367  X.org libXpm up to 3.5.4 xpmNextWord out-of-bounds (5448e1bd)](https://vuldb.com/vuln/359124)|A vulnerability identified as problematic has been detected in X.org libXpm up to 3.5.4. The affected element is the function xpmNextWord. The manipulation leads to out-of-bounds read.This vulnerabi|Thu, 23 Apr 2026 08:55:56 +0200|
 |[CVE-2026-34488  i-PRO IP Setting Software up to 5.19 uncontrolled search path (EUVD-2026-25194)](https://vuldb.com/vuln/359123)|A vulnerability categorized as problematic has been discovered in i-PRO IP Setting Software up to 5.19. Impacted is an unknown function. Executing a manipulation can lead to uncontrolled search path.|Thu, 23 Apr 2026 08:55:09 +0200|
 |[CVE-2026-4512  WebDesignBy reCaptcha Plugin up to 1.x on WordPress Setting grecaptcha_js cross site scripting (EUVD-2026-25197)](https://vuldb.com/vuln/359122)|A vulnerability was found in WebDesignBy reCaptcha Plugin up to 1.x on WordPress. It has been rated as problematic. This issue affects the function grecaptcha_js of the component Setting Handler. Perf|Thu, 23 Apr 2026 08:54:44 +0200|
 |[CVE-2026-4106  HT Mega Addons for Elementor Plugin up to 3.0.6 on WordPress Ajax Action information disclosure (EUVD-2026-25196)](https://vuldb.com/vuln/359121)|A vulnerability was found in HT Mega Addons for Elementor Plugin up to 3.0.6 on WordPress. It has been declared as problematic. This vulnerability affects unknown code of the component Ajax Action Han|Thu, 23 Apr 2026 08:54:39 +0200|
 |[CVE-2026-41990  gnupg Libgcrypt up to 1.12.1 out-of-bounds write (EUVD-2026-25193)](https://vuldb.com/vuln/359120)|A vulnerability was found in gnupg Libgcrypt up to 1.12.1. It has been classified as critical. This affects an unknown part. This manipulation causes out-of-bounds write.The identification of this v|Thu, 23 Apr 2026 07:21:33 +0200|
 |[CVE-2026-41989  gnupg Libgcrypt up to 1.10.3/1.11.2/1.12.1 ECDH gcry_pk_decrypt out-of-bounds write (EUVD-2026-25192)](https://vuldb.com/vuln/359119)|A vulnerability was found in gnupg Libgcrypt up to 1.10.3/1.11.2/1.12.1 and classified as critical. Affected by this issue is the function gcry_pk_decrypt of the component ECDH Handler. The manipulati|Thu, 23 Apr 2026 07:21:25 +0200|
 |[CVE-2026-3007  Three Learning Koollab Learning Management System 5.3.2. cross site scripting (EUVD-2026-25170)](https://vuldb.com/vuln/359118)|A vulnerability has been found in Three Learning Koollab Learning Management System 5.3.2. and classified as problematic. Affected by this vulnerability is an unknown functionality. The manipulation l|Thu, 23 Apr 2026 07:21:13 +0200|
 

# IBM-X-FORCE-EXCHANGE

 |Title|Description|Date|
 |---|---|---|
 |[IBM Guardium Data Protection cross-site scripting (CVE-2026-4918)](https://exchange.xforce.ibmcloud.com/activity/list?filter=Vulnerabilities)|Visit link for details|Apr 22, 2026|
 |[IBM Guardium Data Protection cross-site scripting (CVE-2026-4919)](https://exchange.xforce.ibmcloud.com/activity/list?filter=Vulnerabilities)|Visit link for details|Apr 22, 2026|
 |[IBM WebSphere Application Server Liberty spoofing (CVE-2026-3621)](https://exchange.xforce.ibmcloud.com/activity/list?filter=Vulnerabilities)|Visit link for details|Apr 22, 2026|
 |[radare2 < 6.1.4 Command Injection via PDB Parser Symbol Names (CVE-2026-40517)](https://exchange.xforce.ibmcloud.com/activity/list?filter=Vulnerabilities)|Visit link for details|Apr 22, 2026|
 |[New vulnerability](https://exchange.xforce.ibmcloud.com/activity/list?filter=Vulnerabilities)|Visit link for details|Apr 22, 2026|
 |[](https://exchange.xforce.ibmcloud.com/activity/list?filter=Vulnerabilities)|Visit link for details||
 |[](https://exchange.xforce.ibmcloud.com/activity/list?filter=Vulnerabilities)|Visit link for details||
 |[](https://exchange.xforce.ibmcloud.com/activity/list?filter=Vulnerabilities)|Visit link for details||
 |[](https://exchange.xforce.ibmcloud.com/activity/list?filter=Vulnerabilities)|Visit link for details||
 |[](https://exchange.xforce.ibmcloud.com/activity/list?filter=Vulnerabilities)|Visit link for details||
 

# EU-CERT

 |Title|Description|Date|
 |---|---|---|
 |[2026-004: Critical Vulnerability in SharePoint Exploited](https://cert.europa.eu/publications/security-advisories/2026-004/)|On 17 March 2026, Microsoft updated one of its January 2026 security advisories related to a remote code execution vulnerability in Microsoft SharePoint. Specifically, Microsoft raised the CVSS score and changed the FAQ section to indicate that the vulnerability could be exploited by an unauthenticated attacker. This vulnerability was added in the CISA's Known Exploited Vulnerabilities (KEV) catalogue on 18 March 2026.|Wednesday, March 25, 2026 08:51:39 AM CET|
 |[2026-003: Multiple Vulnerabilities in Citrix NetScaler and Citrix ADC](https://cert.europa.eu/publications/security-advisories/2026-003/)|On 23 March 2026, Citrix published a security advisory addressing multiple vulnerabilities affecting NetScaler ADC and NetScaler Gateway. These vulnerabilities may lead to sensitive information disclosure and user session mix-up under specific configurations.|Monday, March 23, 2026 07:03:59 PM CET|
 |[2026-002: Multiple Vulnerabilities in Cisco Products](https://cert.europa.eu/publications/security-advisories/2026-002/)|On 25 February 2026, Cisco released security advisories addressing multiple high and critical severity vulnerabilities in Cisco Catalyst SD-WAN controllers and Cisco SD-WAN Manager. If exploited, these vulnerabilities could allow attackers to gain administrative access to compromised systems. |Thursday, February 26, 2026 07:38:52 PM CET|
 |[2026-001: Critical vulnerabilities in Ivanti EPMM](https://cert.europa.eu/publications/security-advisories/2026-001/)|On 29 January 2026, Ivanti released a security advisory addressing two critical vulnerabilities in their EPMM products. An attacker could exploit those flaws to achieve unauthenticated remote code execution on the vulnerable device. One of these vulnerabilities have been exploited in a limited number of cases.|Friday, January 30, 2026 10:09:06 AM CET|
 

# MA-CERT

 |Title|Description|Date|
 |---|---|---|
 |[ 63492304/26 - Vulnérabilité activement exploitée affectant Microsoft SharePoint Server ](https://www.dgssi.gov.ma/fr/bulletins/vulnerabilite-activement-exploitee-affectant-microsoft-sharepoint-server)| La vulnérabilité affectant les versions susmentionnées de Microsoft SharePoint Server, identifiée par «CVE-2026-32201» et qui a fait l’objet du bulletin «63121504/26» de la DGSSI est activement…| |
 |[ 63482204/26 - Vulnérabilités critiques activement exploitée affectant Cisco Catalyst… ](https://www.dgssi.gov.ma/fr/bulletins/vulnerabilites-critiques-activement-exploitee-affectant-cisco-catalyst-sd-wan-manager)| Trois vulnérabilités critiques affectant les versions susmentionnées de   Cisco Catalyst SD-WAN Manager et qui ont fait l’objet du bulletin de sécurité « 61462602/26 » de la DGSSI…| |
 |[ 63472204/26 - Vulnérabilité affectant ASP.NET Core ](https://www.dgssi.gov.ma/fr/bulletins/vulnerabilite-affectant-aspnet-core)| Microsoft annonce la correction d’une vulnérabilité affectant les versions susmentionnées d’ASP.NET Core.  L'exploitation  de cette vulnérabilité peut permettre à un attaquant distant…| |
 |[ 63462204/26 - Vulnérabilités dans GoAnywhere Managed File Transfer (MFT) ](https://www.dgssi.gov.ma/fr/bulletins/vulnerabilites-dans-goanywhere-managed-file-transfer-mft)| Fortra a publié un avis de sécurité concernant deux vulnérabilités affectant la solution de transfert de fichiers GoAnywhere MFT.Ces failles sont dues à l’absence de limitation des tentatives…| |
 |[ 63452204/26 - Vulnérabilités critiques dans les produits Atlassian ](https://www.dgssi.gov.ma/fr/bulletins/vulnerabilites-critiques-dans-les-produits-atlassian-1)| Atlassian a publié des mises à jour de sécurité corrigeant plusieurs vulnérabilités affectant les produits susmentionnés. L’exploitation réussie de ces failles peut entraîner une exécution du code…| |
 |[ 63442204/26 - “ Prometei ” malware ](https://www.dgssi.gov.ma/fr/bulletins/prometei-malware)|| |
 |[ 63422204/26 - Vulnérabilités affectant le client de messagerie Mozilla Thunderbird ](https://www.dgssi.gov.ma/fr/bulletins/vulnerabilites-affectant-le-client-de-messagerie-mozilla-thunderbird-15)| Mozilla Foundation annonce la disponibilité d'une mise à jour de sécurité permettant de corriger plusieurs vulnérabilités affectant les versions susmentionnées de son client de messagerie Mozilla…| |
 |[ 63412204/26 - Vulnérabilités affectant le navigateur Mozilla Firefox ](https://www.dgssi.gov.ma/fr/bulletins/vulnerabilites-affectant-le-navigateur-mozilla-firefox-24)| Mozilla Foundation annonce la disponibilité d’une mise à jour de sécurité permettant la     correction de plusieurs vulnérabilités au niveau du navigateur Mozilla Firefox.…| |
 |[ 63432204/26 - "Oracle Critical Patch Update" du Mois Avril 2026 ](https://www.dgssi.gov.ma/fr/bulletins/oracle-critical-patch-update-du-mois-avril-2026)| Oracle a publié son Critical Patch Update (CPU) d’avril 2026, corrigeant plusieurs vulnérabilités critiques affectant les produits susmentionnés.Certaines de ces vulnérabilités sont critiques et…| |
 |[ 63402104/26 - Vulnérabilité critique activement exploitée affectant JetBrains TeamCity ](https://www.dgssi.gov.ma/fr/bulletins/vulnerabilite-critique-activement-exploitee-affectant-jetbrains-teamcity)| Une vulnérabilité critique, activement exploitée, affectant les versions susmentionnées de JetBrains TeamCity a été corrigée. Son exploitation peut permettre à un attaquant distant non authentifié de…| |
 

# ZERODAYINITIATIVE

 |Title|Description|Date|
 |---|---|---|
 |[(0Day) PublicCMS getXml Server-Side Request Forgery Information Disclosure Vulnerability](https://www.zerodayinitiative.com/advisories/ZDI-26-295/)|Visit link for details|2026-04-21|
 |[(0Day) Microsoft Windows library-ms NTLM Response Information Disclosure Vulnerability](https://www.zerodayinitiative.com/advisories/ZDI-26-294/)|Visit link for details|2026-04-21|
 |[(0Day) Microsoft Office URI Handler NTLM Response Information Disclosure Vulnerability](https://www.zerodayinitiative.com/advisories/ZDI-26-293/)|Visit link for details|2026-04-21|
 |[QNAP TS-453E QVRPro excpostgres Exposed Dangerous Method Remote Code Execution Vulnerability](https://www.zerodayinitiative.com/advisories/ZDI-26-292/)|Visit link for details|2026-04-15|
 |[NI LabVIEW LVCLASS File Parsing Memory Corruption Remote Code Execution Vulnerability](https://www.zerodayinitiative.com/advisories/ZDI-26-291/)|Visit link for details|2026-04-15|
 |[NI LabVIEW LVLIB File Parsing Memory Corruption Remote Code Execution Vulnerability](https://www.zerodayinitiative.com/advisories/ZDI-26-290/)|Visit link for details|2026-04-15|
 |[Linux Kernel ETS Scheduler Race Condition Local Privilege Escalation Vulnerability](https://www.zerodayinitiative.com/advisories/ZDI-26-289/)|Visit link for details|2026-04-15|
 

# HK-CERT

 |Title|Description|Date|
 |---|---|---|
 |[Apple Products Information Disclosure Vulnerability](https://www.hkcert.org/security-bulletin/apple-products-information-disclosure-vulnerability_20260423)|A vulnerability has been identified in Apple Products. A remote attacker could exploit this vulnerability to trigger sensitive information disclosure on the targeted system.|Release Date: 23 Apr 2026 |
 |[Botnet Alert - Mirai Botnet Targets End-of-Life D-Link Routers](https://www.hkcert.org/security-bulletin/botnet-alert-mirai-botnet-targets-end-of-life-d-link-routers_20260423)||Release Date: 23 Apr 2026 |
 |[Microsoft Monthly Security Update (April 2026)](https://www.hkcert.org/security-bulletin/microsoft-monthly-security-update-april-2026)|[Updated on 2026-04-17]Updated Description.Proof of Concept exploit code is publicly available for CVE-2026-33825. Insufficient granularity of access control in Microsoft Defender allows an authorized attacker to elevate privileges locally. [Updated on 2026-04...| Release Date: 15 Apr 2026 |
 |[RedHat Linux Kernel Multiple Vulnerabilities](https://www.hkcert.org/security-bulletin/redhat-linux-kernel-multiple-vulnerabilities_20260401)|Multiple vulnerabilities were identified in RedHat Linux Kernel. A remote attacker could exploit some of these vulnerabilities to trigger security restriction bypass, remote code execution, data manipulation, denial of service condition, elevation of privilege and sensitive information disclosure on the targeted system. [Updated on...| Release Date: 1 Apr 2026 |
 |[Mozilla Products Multiple Vulnerabilities](https://www.hkcert.org/security-bulletin/mozilla-products-multiple-vulnerabilities_20260422)|Multiple vulnerabilities were identified in Mozilla Products. A remote attacker could exploit some of these vulnerabilities to trigger denial of service condition, elevation of privilege, remote code execution, security restriction bypass, spoofing and sensitive information disclosure on the targeted system.|Release Date: 22 Apr 2026 |
 |[Oracle Products Multiple Vulnerabilities](https://www.hkcert.org/security-bulletin/oracle-products-multiple-vulnerabilities_20260422)|Multiple vulnerabilities were identified in Oracle Products, a remote attacker could exploit some of these vulnerabilities to trigger elevation of privilege, denial of service condition, remote code execution, sensitive information disclosure, data manipulation and security restriction bypass on the targeted system....|Release Date: 22 Apr 2026 |
 |[PaperCut Multiple Vulnerabilities](https://www.hkcert.org/security-bulletin/papercut-multiple-vulnerabilities_20260421)|Multiple vulnerabilities were identified in PaperCut. A remote attacker could exploit these vulnerabilities to trigger security restriction bypass and remote code execution on the targeted system. Note:CVE-2023-27351 is being exploited in the wild. A remote attacker could leverage this...|Release Date: 21 Apr 2026 |
 |[Zimbra Collaboration Suite Information Disclosure Vulnerability](https://www.hkcert.org/security-bulletin/zimbra-collaboration-suite-cross-site-scripting-vulnerability_20260421)|A vulnerability has been identified in Zimbra Collaboration Suite. A remote attacker could exploit this vulnerability to trigger cross-site scripting and sensitive information disclosure the targeted system. Note:CVE-2025-48700 is being exploited in the wild. This vulnerability could allow...|Release Date: 21 Apr 2026 |
 |[SUSE Linux Kernel Multiple Vulnerabilities](https://www.hkcert.org/security-bulletin/suse-linux-kernel-multiple-vulnerabilities_20260408)|Multiple vulnerabilities were identified in SUSE Linux Kernel. A remote attacker could exploit some of these vulnerabilities to trigger denial of service condition, elevation of privilege, security restriction bypass and data manipulation on the targeted system. [Updated on 2026-04-10]Updated System...| Release Date: 8 Apr 2026 |
 |[Microsoft Edge Multiple Vulnerabilities](https://www.hkcert.org/security-bulletin/microsoft-edge-multiple-vulnerabilities_20260420)|Multiple vulnerabilities were identified in Microsoft Edge. A remote attacker could exploit some of these vulnerabilities to trigger remote code execution, denial of service condition, security restriction bypass and sensitive information disclosure on the targeted system.|Release Date: 20 Apr 2026 |
 

# CA-CCS

 |Title|Description|Date|
 |---|---|---|
 |[Microsoft security advisory – April 2026 monthly rollup (AV26-352) - Update 2](https://www.cyber.gc.ca/en/alerts-advisories/microsoft-security-advisory-april-2026-monthly-rollup-av26-352)|Visit link for details|2026-04-22|
 |[Apple security advisory (AV26-381)](https://www.cyber.gc.ca/en/alerts-advisories/apple-security-advisory-av26-381)|Visit link for details|2026-04-22|
 |[Oracle security advisory – April 2026 quarterly rollup (AV26-380)](https://www.cyber.gc.ca/en/alerts-advisories/oracle-security-advisory-april-2026-quarterly-rollup-av26-380)|Visit link for details|2026-04-22|
 |[n8n security advisory (AV26-379)](https://www.cyber.gc.ca/en/alerts-advisories/n8n-security-advisory-av26-379)|Visit link for details|2026-04-22|
 |[[Control Systems] Phoenix Contact Security Advisory (AV26-378)](https://www.cyber.gc.ca/en/alerts-advisories/control-systems-phoenix-contact-security-advisory-av26-378)|Visit link for details|2026-04-22|
 |[Microsoft security advisory (AV26-377)](https://www.cyber.gc.ca/en/alerts-advisories/microsoft-security-advisory-av26-377)|Visit link for details|2026-04-22|
 |[GitLab security advisory (AV26-376)](https://www.cyber.gc.ca/en/alerts-advisories/gitlab-security-advisory-av26-376)|Visit link for details|2026-04-22|
 |[Atlassian security advisory (AV26-375)](https://www.cyber.gc.ca/en/alerts-advisories/atlassian-security-advisory-av26-375)|Visit link for details|2026-04-21|
 |[Fortra security advisory (AV26-374)](https://www.cyber.gc.ca/en/alerts-advisories/fortra-security-advisory-av26-374)|Visit link for details|2026-04-21|
 |[Spring security advisory (AV26-373)](https://www.cyber.gc.ca/en/alerts-advisories/spring-security-advisory-av26-373)|Visit link for details|2026-04-21|
 