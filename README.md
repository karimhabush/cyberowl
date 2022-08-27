
 <div id='top'></div>

# CyberOwl

 > Last Updated 27/08/2022 21:09:44 UTC
 
 A daily updated summary of the most frequent types of security incidents currently being reported from different sources.
 
 For more information, please check out the documentation [here](./docs/README.md).
 
 ---
 |CyberOwl Sources|Description|
 |---|---|
 |[US-CERT](#us-cert-arrow_heading_up)|United States Computer Emergency and Readiness Team.|
 |[MA-CERT](#ma-cert-arrow_heading_up)|Moroccan Computer Emergency Response Team.|
 |[CERT-FR](#cert-fr-arrow_heading_up)|The French national government Computer Security Incident Response Team.|
 |[IBM X-Force Exchange](#ibmcloud-arrow_heading_up)|A cloud-based threat intelligence platform that allows to consume, share and act on threat intelligence.|
 |[ZeroDayInitiative](#zerodayinitiative-arrow_heading_up)|An international software vulnerability initiative that was started in 2005 by TippingPoint.|
 |[OBS Vigilance](#obs-vigilance-arrow_heading_up)|Vigilance is an initiative created by OBS (Orange Business Services) since 1999 to watch public vulnerabilities and then offer security fixes, a database and tools to remediate them.|
 |[VulDB](#vuldb-arrow_heading_up)|Number one vulnerability database documenting and explaining security vulnerabilities, threats, and exploits since 1970.|
 
 > Suggest a source by opening an [issue](https://github.com/karimhabush/cyberowl/issues)! :raised_hands:
 ---

## US-CERT [:arrow_heading_up:](#cyberowl)

 |Title|Description|Date|
 |---|---|---|
 |[Cisco Releases Security Updates for Multiple Products](https://www.cisa.gov/uscert/ncas/current-activity/2022/08/25/cisco-releases-security-updates-multiple-products)|<p>Cisco has released security updates for vulnerabilities affecting ACI Multi-Site Orchestrator, FXOS, and NX-OS software. A remote attacker could exploit some of these vulnerabilities to take control of an affected system. For updates addressing lower severity vulnerabilities, see the <a href="https://tools.cisco.com/security/center/publicationListing.x">Cisco Security Advisories page</a>.</p>|Thursday, August 25, 2022|
 |[CISA releases 1 Industrial Control Systems Advisory](https://www.cisa.gov/uscert/ncas/current-activity/2022/08/25/cisa-releases-1-industrial-control-systems-advisory)|<p>CISA has released 1 Industrial Control Systems (ICS) advisory on August 25, 2022. This advisory provides timely information about current security issues, vulnerabilities, and exploits surrounding ICS.</p>|Thursday, August 25, 2022|
 |[CISA Adds Ten Known Exploited Vulnerabilities to Catalog](https://www.cisa.gov/uscert/ncas/current-activity/2022/08/25/cisa-adds-ten-known-exploited-vulnerabilities-catalog)|<p>CISA has added ten new vulnerabilities to its <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog">Known Exploited Vulnerabilities Catalog</a>, based on evidence of active exploitation. These types of vulnerabilities are a frequent attack vector for malicious cyber actors and pose significant risk to the federal enterprise. <b>Note:</b> to view the newly added vulnerabilities in the catalog, click on the arrow in the "Date Added to Catalog" column, which will sort by descending dates.      </p>|Thursday, August 25, 2022|
 |[Preparing Critical Infrastructure for Post-Quantum Cryptography](https://www.cisa.gov/uscert/ncas/current-activity/2022/08/24/preparing-critical-infrastructure-post-quantum-cryptography)|<p paraeid="{690153db-eccc-4a03-9d38-b57e1ccb27c2}{213}" paraid="327713930">CISA has released <a href="https://cisa.gov/sites/default/files/publications/cisa_insight_post_quantum_cryptography_508.pdf">CISA Insights: Preparing Critical Infrastructure for Post-Quantum Cryptography</a>, which outlines the actions that critical infrastructure stakeholders should take now to prepare for their future migration to the post-quantum cryptographic standard that the National Institute of Standards and Technology (NIST) will publish in 2024.  </p>|Wednesday, August 24, 2022|
 |[VMware Releases Security Update](https://www.cisa.gov/uscert/ncas/current-activity/2022/08/23/vmware-releases-security-update)|<p>VMware has released a security update to address a vulnerability in Tools. A remote attacker could likely exploit the vulnerability to take control of an affected system.</p>|Tuesday, August 23, 2022|
 |[Mozilla Releases Security Updates for Firefox, Firefox ESR, and Thunderbird](https://www.cisa.gov/uscert/ncas/current-activity/2022/08/23/mozilla-releases-security-updates-firefox-firefox-esr-and)|<p>Mozilla has released security updates to address vulnerabilities in Firefox, Firefox ESR, and Thunderbird. An attacker could exploit some of these vulnerabilities to take control of an affected system. </p>|Tuesday, August 23, 2022|
 
 ---

## CERT-FR [:arrow_heading_up:](#cyberowl)

 |Title|Description|Date|
 |---|---|---|
 |[Multiples vulnérabilités dans le noyau Linux de SUSE](https://www.cert.ssi.gouv.fr/avis/CERTFR-2022-AVI-774/)|De multiples vulnérabilités ont été découvertes dans le noyau Linux de SUSE. Certaines d'entre elles permettent à un attaquant de provoquer un déni de service à distance, un contournement de la politique de sécurité et une atteinte à l'intégrité des données.|Publié le 26 août 2022|
 |[Multiples vulnérabilités dans le noyau Linux d’Ubuntu](https://www.cert.ssi.gouv.fr/avis/CERTFR-2022-AVI-773/)|De multiples vulnérabilités ont été découvertes dans le noyau Linux d'Ubuntu. Elles permettent à un attaquant de provoquer une exécution de code arbitraire, un déni de service et une atteinte à la confidentialité des données.|Publié le 26 août 2022|
 |[Multiples vulnérabilités dans Tenable Nessus Agent](https://www.cert.ssi.gouv.fr/avis/CERTFR-2022-AVI-772/)|De multiples vulnérabilités ont été découvertes dans Tenable Nessus Agent. Elles permettent à un attaquant de provoquer une exécution de code arbitraire à distance, un contournement de la politique de sécurité et une atteinte à la confidentialité des données.|Publié le 26 août 2022|
 |[Multiples vulnérabilités dans SonicWall SMA](https://www.cert.ssi.gouv.fr/avis/CERTFR-2022-AVI-771/)|De multiples vulnérabilités ont été découvertes dans SonicWall SMA. Elles permettent à un attaquant de provoquer une exécution de code arbitraire à distance, un déni de service à distance et une atteinte à la confidentialité des données.|Publié le 25 août 2022|
 |[Vulnérabilité dans ElasticSearch Cloud Enterprise](https://www.cert.ssi.gouv.fr/avis/CERTFR-2022-AVI-770/)|Une vulnérabilité a été découverte dans ElasticSearch Cloud Enterprise. Elle permet à un attaquant de provoquer une atteinte à la confidentialité des données.|Publié le 25 août 2022|
 |[Multiples vulnérabilités dans les produits Cisco](https://www.cert.ssi.gouv.fr/avis/CERTFR-2022-AVI-769/)|De multiples vulnérabilités ont été découvertes dans les produits Cisco. Elles permettent à un attaquant de provoquer une exécution de code arbitraire à distance, un déni de service à distance et une élévation de privilèges.|Publié le 25 août 2022|
 |[Multiples vulnérabilités dans le noyau Linux d’Ubuntu](https://www.cert.ssi.gouv.fr/avis/CERTFR-2022-AVI-768/)|De multiples vulnérabilités ont été corrigées dans le noyau Linux d'|Publié le 25 août 2022|
 |[Multiples vulnérabilités dans les produits IBM](https://www.cert.ssi.gouv.fr/avis/CERTFR-2022-AVI-767/)|De multiples vulnérabilités ont été découvertes dans les produits IBM. Certaines d'entre elles permettent à un attaquant de provoquer une exécution de code arbitraire à distance, un déni de service à distance et un contournement de la politique de sécurité.|Publié le 24 août 2022|
 |[Multiples vulnérabilités dans le noyau Linux de SUSE](https://www.cert.ssi.gouv.fr/avis/CERTFR-2022-AVI-766/)|De multiples vulnérabilités ont été corrigées dans |Publié le 24 août 2022|
 |[Multiples vulnérabilités dans les produits Mozilla](https://www.cert.ssi.gouv.fr/avis/CERTFR-2022-AVI-765/)|De multiples vulnérabilités ont été corrigées dans |Publié le 24 août 2022|
 
 ---

## VulDB [:arrow_heading_up:](#cyberowl)

 |Title|Description|Date|
 |---|---|---|
 |[Schroot denial of service](https://vuldb.com/?id.207428)|Visit link for details|2022-08-27 at 17:02|
 |[Fatek FvDesigner Project File out-of-bounds write](https://vuldb.com/?id.207427)|Visit link for details|2022-08-27 at 16:06|
 |[tcpdump VRRP Parser print-vrrp.c vrrp_print buffer over-read](https://vuldb.com/?id.207426)|Visit link for details|2022-08-27 at 16:05|
 |[oretnom23 Fast Food Ordering System cross site scripting](https://vuldb.com/?id.207425)|Visit link for details|2022-08-27 at 10:49|
 |[SourceCodester Simple Task Managing System cross site scripting](https://vuldb.com/?id.207424)|Visit link for details|2022-08-27 at 10:47|
 |[SourceCodester Simple Task Managing System loginVaLidation.php sql injection](https://vuldb.com/?id.207423)|Visit link for details|2022-08-27 at 10:45|
 |[oretnom23 Fast Food Ordering System index.php sql injection](https://vuldb.com/?id.207422)|Visit link for details|2022-08-27 at 10:43|
 |[Keycloak Admin Console cross site scripting](https://vuldb.com/?id.207421)|Visit link for details|2022-08-27 at 08:19|
 |[Foreman Datacenter Plugin information disclosure](https://vuldb.com/?id.207420)|Visit link for details|2022-08-27 at 08:18|
 |[Deluge Web UI cross site scripting](https://vuldb.com/?id.207419)|Visit link for details|2022-08-27 at 08:17|
 
 ---

## IBMCLOUD [:arrow_heading_up:](#cyberowl)

 |Title|Description|Date|
 |---|---|---|
 |[SEO Scout plugin for WordPress cross-site request forgery (CVE-2022-36358)](https://exchange.xforce.ibmcloud.com/activity/list?filter=Vulnerabilities)|Visit link for details|Aug 25, 2022|
 |[Claroline cross-site request forgery (CVE-2022-37160)](https://exchange.xforce.ibmcloud.com/activity/list?filter=Vulnerabilities)|Visit link for details|Aug 25, 2022|
 |[Claroline cross-site scripting (CVE-2022-37161)](https://exchange.xforce.ibmcloud.com/activity/list?filter=Vulnerabilities)|Visit link for details|Aug 25, 2022|
 |[Claroline cross-site scripting (CVE-2022-37162)](https://exchange.xforce.ibmcloud.com/activity/list?filter=Vulnerabilities)|Visit link for details|Aug 25, 2022|
 |[Apache Hadoop command execution (CVE-2021-25642)](https://exchange.xforce.ibmcloud.com/activity/list?filter=Vulnerabilities)|Visit link for details|Aug 25, 2022|
 |[Apache libapreq2 denial of service (CVE-2022-22728)](https://exchange.xforce.ibmcloud.com/activity/list?filter=Vulnerabilities)|Visit link for details|Aug 25, 2022|
 |[Ap Pagebuilder module for PrestaShop SQL injection (CVE-2022-22897)](https://exchange.xforce.ibmcloud.com/activity/list?filter=Vulnerabilities)|Visit link for details|Aug 25, 2022|
 
 ---

## ZeroDayInitiative [:arrow_heading_up:](#cyberowl)

 |Title|Description|Date|
 |---|---|---|
 |[Fatek Automation FvDesigner FPJ File Parsing Out-Of-Bounds Write Remote Code Execution Vulnerability](https://www.zerodayinitiative.com/advisories/ZDI-22-1174/)|Visit link for details|Aug. 25, 2022|
 |[Fatek Automation FvDesigner FPJ File Parsing Out-Of-Bounds Write Remote Code Execution Vulnerability](https://www.zerodayinitiative.com/advisories/ZDI-22-1173/)|Visit link for details|Aug. 25, 2022|
 |[Fatek Automation FvDesigner FPJ File Parsing Out-Of-Bounds Write Remote Code Execution Vulnerability](https://www.zerodayinitiative.com/advisories/ZDI-22-1172/)|Visit link for details|Aug. 25, 2022|
 |[Fatek Automation FvDesigner FPJ File Parsing Out-Of-Bounds Write Remote Code Execution Vulnerability](https://www.zerodayinitiative.com/advisories/ZDI-22-1171/)|Visit link for details|Aug. 25, 2022|
 |[Fatek Automation FvDesigner FPJ File Parsing Out-Of-Bounds Write Remote Code Execution Vulnerability](https://www.zerodayinitiative.com/advisories/ZDI-22-1170/)|Visit link for details|Aug. 25, 2022|
 |[Fatek Automation FvDesigner FPJ File Parsing Out-Of-Bounds Write Remote Code Execution Vulnerability](https://www.zerodayinitiative.com/advisories/ZDI-22-1169/)|Visit link for details|Aug. 25, 2022|
 |[Fatek Automation FvDesigner FPJ File Parsing Out-Of-Bounds Write Remote Code Execution Vulnerability](https://www.zerodayinitiative.com/advisories/ZDI-22-1168/)|Visit link for details|Aug. 25, 2022|
 |[Fatek Automation FvDesigner FPJ File Parsing Out-Of-Bounds Write Remote Code Execution Vulnerability](https://www.zerodayinitiative.com/advisories/ZDI-22-1167/)|Visit link for details|Aug. 25, 2022|
 
 ---

## OBS-Vigilance [:arrow_heading_up:](#cyberowl)

 |Title|Description|Date|
 |---|---|---|
 |[<a href="https://vigilance.fr/vulnerability/libyang-assertion-error-via-lys-node-free-39126" class="noirorange"><b>libyang</b>: assertion error via lys_node_free()</a>](https://vigilance.fr/vulnerability/libyang-assertion-error-via-lys-node-free-39126)|An attacker can force an assertion error of libyang, via lys_node_free(), in order to trigger a denial of service...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/Linux-kernel-out-of-bounds-memory-reading-via-bpf-tail-call-39125" class="noirorange"><b>Linux kernel</b>: out-of-bounds memory reading via bpf_tail_call()</a>](https://vigilance.fr/vulnerability/Linux-kernel-out-of-bounds-memory-reading-via-bpf-tail-call-39125)|An attacker can force a read at an invalid memory address of the Linux kernel, via bpf_tail_call(), in order to trigger a denial of service, or to obtain sensitive information...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/SQLite-denial-of-service-via-fts5UnicodeTokenize-39124" class="noirorange"><b>SQLite</b>: denial of service via <wbr>fts5UnicodeTokenize(<wbr>)</wbr></wbr></a>](https://vigilance.fr/vulnerability/SQLite-denial-of-service-via-fts5UnicodeTokenize-39124)|An attacker can cause a fatal error of SQLite, via |Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/Vim-NULL-pointer-dereference-via-sug-filltree-39122" class="noirorange"><b>Vim</b>: NULL pointer dereference via sug_filltree()</a>](https://vigilance.fr/vulnerability/Vim-NULL-pointer-dereference-via-sug-filltree-39122)|An attacker can force a NULL pointer to be dereferenced on Vim, via sug_filltree(), in order to trigger a denial of service...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/Vim-reuse-after-free-via-tagfunc-39121" class="noirorange"><b>Vim</b>: reuse after free via tagfunc</a>](https://vigilance.fr/vulnerability/Vim-reuse-after-free-via-tagfunc-39121)|An attacker can force the reuse of a freed memory area of Vim, via tagfunc, in order to trigger a denial of service, and possibly to run code...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/Apereo-CAS-Server-user-access-via-OpenID-Connect-39120" class="noirorange"><b>Apereo CAS Server</b>: user access via OpenID Connect</a>](https://vigilance.fr/vulnerability/Apereo-CAS-Server-user-access-via-OpenID-Connect-39120)|An attacker can bypass restrictions of Apereo CAS Server, via OpenID Connect, in order to gain user privileges...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/HCL-Domino-iNotes-user-access-via-Password-Strength-Checks-39119" class="noirorange"><b>HCL Domino  iNotes</b>: user access via Password Strength Checks</a>](https://vigilance.fr/vulnerability/HCL-Domino-iNotes-user-access-via-Password-Strength-Checks-39119)|An attacker can bypass restrictions of HCL Domino  iNotes, via Password Strength Checks, in order to gain user privileges...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/HCL-Domino-iNotes-information-disclosure-via-Non-existent-Domain-Link-39118" class="noirorange"><b>HCL Domino  iNotes</b>: information disclosure via Non-existent Domain Link</a>](https://vigilance.fr/vulnerability/HCL-Domino-iNotes-information-disclosure-via-Non-existent-Domain-Link-39118)|An attacker can bypass access restrictions to data of HCL Domino  iNotes, via Non-existent Domain Link, in order to read sensitive information...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/HCL-Domino-iNotes-Cross-Site-Scripting-via-Form-POST-Request-39117" class="noirorange"><b>HCL Domino  iNotes</b>: Cross Site Scripting via Form POST Request</a>](https://vigilance.fr/vulnerability/HCL-Domino-iNotes-Cross-Site-Scripting-via-Form-POST-Request-39117)|An attacker can trigger a Cross Site Scripting of HCL Domino  iNotes, via Form POST Request, in order to run JavaScript code in the context of the web site...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/Linux-kernel-memory-corruption-via-pipe-resize-ring-39116" class="noirorange"><b>Linux kernel</b>: memory corruption via pipe_resize_ring()</a>](https://vigilance.fr/vulnerability/Linux-kernel-memory-corruption-via-pipe-resize-ring-39116)|An attacker can trigger a memory corruption of the Linux kernel, via pipe_resize_ring(), in order to trigger a denial of service, and possibly to run code...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/systemd-reuse-after-free-via-DnsStream-39115" class="noirorange"><b>systemd</b>: reuse after free via DnsStream</a>](https://vigilance.fr/vulnerability/systemd-reuse-after-free-via-DnsStream-39115)|An attacker can force the reuse of a freed memory area of systemd, via DnsStream, in order to trigger a denial of service, and possibly to run code...|Visit link for details|
 
 ---

## MA-CERT [:arrow_heading_up:](#cyberowl)

 |Title|Description|Date|
 |---|---|---|
 |[37962608/22 - Vulnérabilités dans SonicWall SMA](/fr/content/3796260822-vulnerabilites-dans-sonicwall-sma.html)|Une vulnérabilité a été corrigée dans SonicWall SMA. L'exploitation de cette faille peut permettre à un attaquant distant d’exécuter des commandes arbitraires, de causer un déni de service ou de porter atteinte à la confidentialité de...|26 août 2022|
 |[37952608/22 - Vulnérabilités dans Sophos UTM](/fr/content/3795260822-vulnerabilites-dans-sophos-utm.html)|Plusieurs vulnérabilités ont été corrigées affectant Sophos UTM. L’exploitation de ces failles peut permettre à un attaquant distant d’exécuter du code arbitraire ou de contourner la politique de sécurité.|26 août 2022|
 |[37942508/22 - Vulnérabilités affectant des produits d’IBM ](/fr/content/3794250822-vulnerabilites-affectant-des-produits-d-ibm.html)|IBM annonce la correction de plusieursvulnérabilités affectant ses produits susmentionnés. L’exploitation de ces failles permet à un attaquant d’exécuter du code arbitraire, de contourner la politique de sécurité, d’accéder à des données...|25 août 2022|
 |[37932508/22 -Vulnérabilités affectant plusieursproduits deCisco](/fr/content/3793250822-vulnerabilites-affectant-plusieurs-produits-de-cisco.html)|Cisco annonce la correction de plusieurs vulnérabilités affectant certaines versions de ses produits susmentionnés.L'exploitation de ces vulnérabilités peutpermettreà un attaquant distant d’exécuter des commandes arbitraires, d’...|25 août 2022|
 |[37922508/22 - Vulnérabilités dans les produits Mozilla ](/fr/content/3792250822-vulnerabilites-dans-les-produits-mozilla.html)|Mozilla a corrigé plusieurs vulnérabilités dans les produits susmentionnés. L’exploitation de ces failles peut permettre à un attaquant d’exécuter du code arbitraire à distance et de contourner la politique de sécurité.|25 août 2022|
 |[37912508/22 - Vulnérabilités dans les produits F-Secure](/fr/content/3791250822-vulnerabilites-dans-les-produits-f-secure.html)|Deux vulnérabilités ont été corrigées dans les produits susmentionnés de F-Secure. L’exploitation de ces failles peut permettre à un attaquant distant de causer un déni de service.|25 août 2022|
 |[3790240822 - Vulnérabilité critique affectant GitLab](/fr/content/3790240822-vulnerabilite-critique-affectant-gitlab.html)|GitLab annonce la disponibilité de mises à jour permettant de corriger une vulnérabilité critique affectant ses produits susmentionnés. L’exploitation de cette vulnérabilité peut permettre à un attaquant distant d’exécuter du code...|24 août 2022|
 |[37892408/22 - Vulnérabilité dans VMware Tools](/fr/content/3789240822-vulnerabilite-dans-vmware-tools.html)|Une vulnérabilité a été corrigée dans VMware Tools pour Windows. Un attaquant pourrait exploiter cette faille afin de réussir une élévation de privilèges en tant qu'utilisateur « root » de la machine virtuelle.|24 août 2022|
 |[37882308/22 - Vulnérabilités dans Microsoft Edge](/fr/content/3788230822-vulnerabilites-dans-microsoft-edge.html)|Microsoft annonce la correction de plusieurs vulnérabilités dans Microsoft Edge. L’exploitation de ces failles peut permettre à un attaquant de provoquer un problème de sécurité non spécifié.|23 août 2022|
 |[37871908/22 - « Zero-Day » affectant le navigateur Apple Safari ](/fr/content/3787190822-zero-day-affectant-le-navigateur-apple-safari.html)|Apple annonce la correction d’une vulnérabilité critique affectant les versions susmentionnées de son navigateur Safari. Selon Apple cette vulnérabilité est activement exploitée et peut permettre à un attaquant distant d’exécuter du code...|19 août 2022|
 |[37861908/22 - Vulnérabilité dans Cisco AsyncOS for Secure Web Appliance](/fr/content/3786190822-vulnerabilite-dans-cisco-asyncos-secure-web-appliance.html)|Une vulnérabilité a été corrigée dans Cisco AsyncOS for Secure Web Appliance. L’exploitation de cette faille pourrait permettre à un attaquant d’exécuter du code arbitraire à distance et de réussir une élévation de privilèges.|19 août 2022|
 