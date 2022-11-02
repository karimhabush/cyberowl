
 <div id='top'></div>

# CyberOwl

 > Last Updated 02/11/2022 09:11:44 UTC
 
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
 |[OpenSSL Releases Security Update](https://www.cisa.gov/uscert/ncas/current-activity/2022/11/01/openssl-releases-security-update)|<p>OpenSSL has released a security advisory to address two vulnerabilities, CVE-2022-3602 and CVE-2022-3786, affecting OpenSSL versions 3.0.0 through 3.0.6.</p>|Tuesday, November 1, 2022|
 |[CISA Upgrades to TLP 2.0](https://www.cisa.gov/uscert/ncas/current-activity/2022/11/01/cisa-upgrades-tlp-20)|<p>Today, CISA officially upgraded to <a href="https://www.cisa.gov/tlp">Traffic Light Protocol (TLP) 2.0</a>, which facilitates greater information sharing and collaboration. CISA made this upgrade in accordance with <a href="https://www.first.org/newsroom/releases/20220805">the recommendation from the Forum of Incident Response and Security Teams to upgrade to TLP 2.0 by January 2023</a>.</p>|Tuesday, November 1, 2022|
 |[CISA Releases One Industrial Control Systems Advisory](https://www.cisa.gov/uscert/ncas/current-activity/2022/11/01/cisa-releases-one-industrial-control-systems-advisory)|<p>CISA released one Industrial Control Systems (ICS) advisory on November 1, 2022. This advisory provides timely information about current security issues, vulnerabilities, and exploits surrounding ICS.</p>|Tuesday, November 1, 2022|
 |[CISA Releases Guidance on Phishing-Resistant and Numbers Matching Multifactor Authentication ](https://www.cisa.gov/uscert/ncas/current-activity/2022/10/31/cisa-releases-guidance-phishing-resistant-and-numbers-matching)|<p>CISA has released two fact sheets to highlight threats against accounts and systems using certain forms of multifactor authentication (MFA). CISA strongly urges all organizations to implement phishing-resistant MFA to protect against phishing and other known cyber threats. If an organization using mobile push-notification-based MFA is unable to implement phishing-resistant MFA, CISA recommends using number matching to mitigate MFA fatigue.</p>|Monday, October 31, 2022|
 |[CISA Has Added One Known Exploited Vulnerability to Catalog](https://www.cisa.gov/uscert/ncas/current-activity/2022/10/28/cisa-has-added-one-known-exploited-vulnerability-catalog)|<p>CISA has added one new vulnerability to its <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog">Known Exploited Vulnerabilities Catalog</a>, based on evidence of active exploitation. This type of vulnerability is a frequent attack vector for malicious cyber actors and pose significant risk to the federal enterprise. Note: To view the newly added vulnerabilities in the catalog, click on the arrow in the "Date Added to Catalog" column, which will sort by descending dates.</p>|Friday, October 28, 2022|
 |[Joint CISA FBI MS-ISAC Guide on Responding to DDoS Attacks and DDoS Guidance for Federal Agencies](https://www.cisa.gov/uscert/ncas/current-activity/2022/10/28/joint-cisa-fbi-ms-isac-guide-responding-ddos-attacks-and-ddos)|<p>CISA, the Federal Bureau of Investigation (FBI), and the Multi-State Information Sharing and Analysis Center (MS-ISAC) have released <em>Understanding and Responding to Distributed Denial-of-Service Attacks</em> to provide organizations proactive steps to reduce the likelihood and impact of distributed denial-of-service (DDoS) attacks. The guidance is for both network defenders and leaders to help them understand and respond to DDoS attacks, which can cost an organization time, money, and reputational damage.</p>|Friday, October 28, 2022|
 
 ---

## CERT-FR [:arrow_heading_up:](#cyberowl)

 |Title|Description|Date|
 |---|---|---|
 |[Vulnérabilité dans Azure CLI](https://www.cert.ssi.gouv.fr/avis/CERTFR-2022-AVI-972/)|Une vulnérabilité a été découverte dans Azure CLI. Elle permet à un attaquant de provoquer une exécution de code arbitraire à distance.|Publié le 31 octobre 2022|
 |[Multiples vulnérabilités dans PHP](https://www.cert.ssi.gouv.fr/avis/CERTFR-2022-AVI-971/)|De multiples vulnérabilités ont été découvertes dans PHP. Elles permettent à un attaquant de provoquer un problème de sécurité non spécifié par l'éditeur et une atteinte à la confidentialité des données.|Publié le 31 octobre 2022|
 |[Vulnérabilité dans Nextcloud Server](https://www.cert.ssi.gouv.fr/avis/CERTFR-2022-AVI-970/)|Une vulnérabilité a été découverte dans Nextcloud Server. Elle permet à un attaquant de provoquer une atteinte à la confidentialité des données.|Publié le 31 octobre 2022|
 |[Vulnérabilité dans les produits NetApp](https://www.cert.ssi.gouv.fr/avis/CERTFR-2022-AVI-969/)|Une vulnérabilité a été découverte dans les produits NetApp. Elle permet à un attaquant de provoquer un déni de service à distance, une atteinte à l'intégrité des données et une atteinte à la confidentialité des données.|Publié le 31 octobre 2022|
 |[Multiples vulnérabilités dans le noyau Linux d’Ubuntu](https://www.cert.ssi.gouv.fr/avis/CERTFR-2022-AVI-968/)|De multiples vulnérabilités ont été découvertes dans le noyau Linux d'Ubuntu. Elles permettent à un attaquant de provoquer une exécution de code arbitraire à distance, un déni de service à distance et une atteinte à la confidentialité des données.|Publié le 28 octobre 2022|
 |[Multiples vulnérabilités dans le noyau Linux de SUSE](https://www.cert.ssi.gouv.fr/avis/CERTFR-2022-AVI-967/)|De multiples vulnérabilités ont été découvertes dans le noyau Linux de SUSE. Certaines d'entre elles permettent à un attaquant de provoquer un problème de sécurité non spécifié par l'éditeur, une exécution de code arbitraire à distance et un déni de service à distance.|Publié le 28 octobre 2022|
 |[Multiples vulnérabilités dans les produits Synology](https://www.cert.ssi.gouv.fr/avis/CERTFR-2022-AVI-966/)|De multiples vulnérabilités ont été découvertes dans les produits Synology. Elles permettent à un attaquant de provoquer un contournement de la politique de sécurité, une atteinte à l'intégrité des données et une atteinte à la confidentialité des données.|Publié le 28 octobre 2022|
 |[Multiples vulnérabilités dans Microsoft Edge](https://www.cert.ssi.gouv.fr/avis/CERTFR-2022-AVI-965/)|De multiples vulnérabilités ont été corrigées dans |Publié le 28 octobre 2022|
 |[Vulnérabilité dans Google Chrome](https://www.cert.ssi.gouv.fr/avis/CERTFR-2022-AVI-964/)|Une vulnérabilité a été découverte dans Google Chrome. Elle permet à un attaquant de provoquer un problème de sécurité non spécifié par l'éditeur.|Publié le 28 octobre 2022|
 |[Multiples vulnérabilités dans Apple iOS et iPadOS](https://www.cert.ssi.gouv.fr/avis/CERTFR-2022-AVI-963/)|De multiples vulnérabilités ont été découvertes dans Apple iOS et iPadOS. Certaines d'entre elles permettent à un attaquant de provoquer une exécution de code arbitraire à distance, un déni de service à distance et un contournement de la politique de sécurité.|Publié le 28 octobre 2022|
 
 ---

## OBS-Vigilance [:arrow_heading_up:](#cyberowl)

 |Title|Description|Date|
 |---|---|---|
 |[<a href="https://vigilance.fr/vulnerability/FreeBSD-memory-leak-via-Unreclaimable-Memory-Pages-39807" class="noirorange"><b>FreeBSD</b>: memory leak via Unreclaimable Memory Pages</a>](https://vigilance.fr/vulnerability/FreeBSD-memory-leak-via-Unreclaimable-Memory-Pages-39807)|An attacker can create a memory leak of FreeBSD, via Unreclaimable Memory Pages, in order to trigger a denial of service...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/FreeBSD-reuse-after-free-via-ZFS-B-Tree-39806" class="noirorange"><b>FreeBSD</b>: reuse after free via ZFS B-Tree</a>](https://vigilance.fr/vulnerability/FreeBSD-reuse-after-free-via-ZFS-B-Tree-39806)|An attacker can force the reuse of a freed memory area of FreeBSD, via ZFS B-Tree, in order to trigger a denial of service, and possibly to run code...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/FFmpeg-buffer-overflow-via-build-open-gop-key-points-39805" class="noirorange"><b>FFmpeg</b>: buffer overflow via <wbr>build_open_gop_key_p<wbr>oints()</wbr></wbr></a>](https://vigilance.fr/vulnerability/FFmpeg-buffer-overflow-via-build-open-gop-key-points-39805)|An attacker can trigger a buffer overflow of FFmpeg, via |Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/Linux-kernel-memory-corruption-via-emulation-proc-handler-39804" class="noirorange"><b>Linux kernel</b>: memory corruption via <wbr>emulation_proc_handl<wbr>er()</wbr></wbr></a>](https://vigilance.fr/vulnerability/Linux-kernel-memory-corruption-via-emulation-proc-handler-39804)|An attacker can trigger a memory corruption of the Linux kernel, via |Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/Linux-kernel-reuse-after-free-via-nilfs-new-inode-39803" class="noirorange"><b>Linux kernel</b>: reuse after free via nilfs_new_inode()</a>](https://vigilance.fr/vulnerability/Linux-kernel-reuse-after-free-via-nilfs-new-inode-39803)|An attacker can force the reuse of a freed memory area of the Linux kernel, via nilfs_new_inode(), in order to trigger a denial of service, and possibly to run code...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/Linux-kernel-memory-leak-via-nilfs-attach-log-writer-39802" class="noirorange"><b>Linux kernel</b>: memory leak via <wbr>nilfs_attach_log_wri<wbr>ter()</wbr></wbr></a>](https://vigilance.fr/vulnerability/Linux-kernel-memory-leak-via-nilfs-attach-log-writer-39802)|An attacker can create a memory leak of the Linux kernel, via |Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/Fortinet-FortiOS-information-disclosure-via-SSL-VPN-Interface-Telnet-39801" class="noirorange"><b>Fortinet FortiOS</b>: information disclosure via SSL-VPN Interface Telnet</a>](https://vigilance.fr/vulnerability/Fortinet-FortiOS-information-disclosure-via-SSL-VPN-Interface-Telnet-39801)|An attacker can bypass access restrictions to data of Fortinet FortiOS, via SSL-VPN Interface Telnet, in order to read sensitive information...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/Fortinet-FortiOS-write-access-via-API-Read-Only-Users-39800" class="noirorange"><b>Fortinet FortiOS</b>: write access via API Read-Only Users</a>](https://vigilance.fr/vulnerability/Fortinet-FortiOS-write-access-via-API-Read-Only-Users-39800)|An attacker can bypass access restrictions of Fortinet FortiOS, via API Read-Only Users, in order to alter data...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/Fortinet-FortiOS-Man-in-the-Middle-via-RSA-SSH-Host-Key-39799" class="noirorange"><b>Fortinet FortiOS</b>: Man-in-the-Middle via RSA SSH Host Key</a>](https://vigilance.fr/vulnerability/Fortinet-FortiOS-Man-in-the-Middle-via-RSA-SSH-Host-Key-39799)|An attacker can act as a Man-in-the-Middle on Fortinet FortiOS, via RSA SSH Host Key, in order to read or write data in the session...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/FortiManager-FortiAnalyzer-Cross-Site-Scripting-via-Report-Templates-39798" class="noirorange"><b>FortiManager  FortiAnalyzer</b>: Cross Site Scripting via Report Templates</a>](https://vigilance.fr/vulnerability/FortiManager-FortiAnalyzer-Cross-Site-Scripting-via-Report-Templates-39798)|An attacker can trigger a Cross Site Scripting of FortiManager  FortiAnalyzer, via Report Templates, in order to run JavaScript code in the context of the web site...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/FortiClient-Mac-information-disclosure-via-FortiTray-Cleartext-SSLVPN-Password-39797" class="noirorange"><b>FortiClient Mac</b>: information disclosure via FortiTray Cleartext SSLVPN Password</a>](https://vigilance.fr/vulnerability/FortiClient-Mac-information-disclosure-via-FortiTray-Cleartext-SSLVPN-Password-39797)|An attacker can bypass access restrictions to data of FortiClient Mac, via FortiTray Cleartext SSLVPN Password, in order to read sensitive information...|Visit link for details|
 
 ---

## MA-CERT [:arrow_heading_up:](#cyberowl)

 |Title|Description|Date|
 |---|---|---|
 |[38950211/22 - Vulnérabilités dans OpenSSL](https://www.dgssi.gov.ma//fr/content/3895021122-vulnerabilites-dans-openssl.html)|OpenSSL a publié un avis de sécurité pour corriger deux vulnérabilités critiqiues « CVE-2022-3602 et CVE-2022-3786 », affectant les versions OpenSSL 3.0.0 à 3.0.6. Les deux vulnérabilités peuvent provoquer un déni de service lors de la...|02 novembre 2022|
 |[38940111/22 - Vulnérabilités dans PHP](https://www.dgssi.gov.ma//fr/content/3894011122-vulnerabilites-dans-php.html)|Deux vulnérabilités ont été corrigées dans les versions de PHP susmentionnées. L’exploitation de ces failles peut permettre à un attaquant de porter atteinte à la confidentialité des données.|01 novembre 2022|
 |[38933110/22 - Publication d'un exploit pour la vulnérabilité critique affectant VMware Cloud Fo](https://www.dgssi.gov.ma//fr/content/3893311022-publication-d-un-exploit-pour-la-vulnerabilite-critique-affectant-vmware-cloud-foundation.html)|VMware confirme la disponibilité d’un exploit de la vulnérabilité critique « CVE-2021-39144 » permettant aux attaquants d'exécuter du code arbitraire à distance avec les privilèges « root » sur les appliances Cloud Foundation et NSX...|31 octobre 2022|
 |[38923110/22 - Vulnérabilité « Zero-Day »affectantle navigateur Google Chrome ](https://www.dgssi.gov.ma//fr/content/3892311022-vulnerabilite-zero-day-affectant-le-navigateur-google-chrome.html)|Google vient de publier une mise à jour de sécurité qui permet de corriger unevulnérabilité « Zero-Day » activement exploitéeaffectant le navigateur Google Chrome. L’exploitation de cette vulnérabilité peut permettre àun attaquant d’...|31 octobre 2022|
 |[38912810/22 - Vulnérabilités dans les produits IBM](https://www.dgssi.gov.ma//fr/content/3891281022-vulnerabilites-dans-les-produits-ibm.html)|Plusieurs vulnérabilités ont été corrigées dans les produits IBM susmentionnés. Un attaquant pourrait exploiter ces failles afin d’exécuter du code arbitraire à distance et de causer undéni de service.|28 octobre 2022|
 |[38902710/22 - Plusieurs vulnérabilités dans les produits Apple](https://www.dgssi.gov.ma//fr/content/3890271022-plusieurs-vulnerabilites-dans-les-produits-apple.html)|Apple a publié des mises à jour de sécurité qui corrigent plusieurs vulnérabilités dans les produits susmentionnés. L’exploitation de ces failles peut permettre à un attaquant d’exécuter du code arbitraire à distance (RCE), de porter...|27 octobre 2022|
 |[38892710/22 - Vulnérabilités affectantdes produits Aruba ](https://www.dgssi.gov.ma//fr/content/3889271022-vulnerabilites-affectant-des-produits-aruba.html)|Aruba Networks annonce la correction deplusieurs vulnérabilités affectant les versions susmentionnées de certains de ses produits. L'exploitation de ces vulnérabilités peutpermettreà un attaquant distant d’exécuter du code...|27 octobre 2022|
 |[38882710/22 - Vulnérabilités dans le CMS Joomla](https://www.dgssi.gov.ma//fr/content/3888271022-vulnerabilites-dans-le-cms-joomla.html)|Deux vulnérabilités ont été corrigées dans le CMS Joomla. L’exploitation de ces failles permet à un attaquant de porter atteinte à la confidentialité de données et de réussir une injection de code indirecte à distance (XSS).|27 octobre 2022|
 |[38862610/22 - Vulnérabilités affectant le client de messagerie Mozilla Thunderbird ](https://www.dgssi.gov.ma//fr/content/3886261022-vulnerabilites-affectant-le-client-de-messagerie-mozilla-thunderbird.html)|Mozilla Foundation annonce la disponibilité d'une mise à jour de sécurité permettant de corriger plusieurs vulnérabilités affectant son client de messagerie Mozilla Thunderbird. L’exploitation de ces vulnérabilités peut permettre à un...|26 octobre 2022|
 |[38872610/22 - Vulnérabilités dansGoogle Chrome](https://www.dgssi.gov.ma//fr/content/3887261022-vulnerabilites-dans-google-chrome.html)|Google a corrigé plusieurs vulnérabilités dans son navigateur Google Chrome. L’exploitation de ces failles peut permettre à un attaquant de prendre le contrôle du système affecté.|26 octobre 2022|
 |[38852610/22 - Vulnérabilités critiques dans VMware Cloud Foundation](https://www.dgssi.gov.ma//fr/content/3885261022-vulnerabilites-critiques-dans-vmware-cloud-foundation.html)|Deux vulnérabilités critiques ont été corrigées dans VMware Cloud Foundation. L’exploitation de ces failles permet à un attaquant d’exécuter des commandes arbitraires à distance avec des privilèges « root ».|26 octobre 2022|
 
 ---

## VulDB [:arrow_heading_up:](#cyberowl)

 |Title|Description|Date|
 |---|---|---|
 |[Huaxia ERP Retail Management list information disclosure](https://vuldb.com/?id.212793)|Visit link for details|2022-11-02 at 10:11|
 |[Huaxia ERP User Management sql injection](https://vuldb.com/?id.212792)|Visit link for details|2022-11-02 at 10:09|
 |[Apple iOS/iPadOS Local Privilege Escalation](https://vuldb.com/?id.212791)|Visit link for details|2022-11-02 at 10:07|
 |[Apple iOS Privacy Preferences access control](https://vuldb.com/?id.212790)|Visit link for details|2022-11-02 at 10:04|
 |[Apple iOS Caches information disclosure](https://vuldb.com/?id.212789)|Visit link for details|2022-11-02 at 10:03|
 |[Apple macOS information disclosure](https://vuldb.com/?id.212788)|Visit link for details|2022-11-02 at 10:02|
 |[Apple watchOS Device Identifier information disclosure](https://vuldb.com/?id.212787)|Visit link for details|2022-11-02 at 10:01|
 |[Apple iOS Device Identifier information disclosure](https://vuldb.com/?id.212786)|Visit link for details|2022-11-02 at 10:01|
 |[Apple iOS denial of service](https://vuldb.com/?id.212785)|Visit link for details|2022-11-02 at 09:58|
 |[Apple watchOS Kernel Local Privilege Escalation](https://vuldb.com/?id.212784)|Visit link for details|2022-11-02 at 09:57|
 