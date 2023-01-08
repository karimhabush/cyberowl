
 <div id='top'></div>

# CyberOwl

 > Last Updated 08/01/2023 09:08:32 UTC
 
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
 |[CISA Releases Three Industrial Systems Control Advisories](https://www.cisa.gov/uscert/ncas/current-activity/2023/01/05/cisa-releases-three-industrial-systems-control-advisories)|<p>CISA released three Industrial Control Systems (ICS) advisories on January 5 2023. These advisories provide timely information about current security issues, vulnerabilities, and exploits surrounding ICS.</p>|Thursday, January 5, 2023|
 |[Fortinet Releases Security Updates for FortiADC](https://www.cisa.gov/uscert/ncas/current-activity/2023/01/04/fortinet-releases-security-updates-fortiadc)|<p>Fortinet has released a security advisory to address a vulnerability in multiple versions of FortiADC. This vulnerability may allow a remote attacker “to execute unauthorized code or commands via specifically crafted HTTP requests.”</p>|Wednesday, January 4, 2023|
 |[CISA Adds Two Known Exploited Vulnerabilities to Catalog](https://www.cisa.gov/uscert/ncas/current-activity/2022/12/29/cisa-adds-two-known-exploited-vulnerabilities-catalog)|<p>CISA has added two new vulnerabilities to its <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog">Known Exploited Vulnerabilities Catalog</a>, based on evidence of active exploitation. These types of vulnerabilities are frequent attack vectors for malicious cyber actors and pose significant risks to the federal enterprise. <strong>Note</strong>: To view the newly added vulnerabilities in the catalog, click on the arrow in the "Date Added to Catalog" column, which will sort by descending dates.</p>|Thursday, December 29, 2022|
 |[CISA Releases Four Industrial Control Systems Advisories](https://www.cisa.gov/uscert/ncas/current-activity/2022/12/22/cisa-releases-four-industrial-control-systems-advisories)|<p>CISA released four Industrial Control Systems (ICS) advisories on December 22, 2022. These advisories provide timely information about current security issues, vulnerabilities, and exploits surrounding ICS.</p>|Thursday, December 22, 2022|
 |[CISA Releases Six Industrial Control Systems Advisories](https://www.cisa.gov/uscert/ncas/current-activity/2022/12/20/cisa-releases-six-industrial-control-systems-advisories)|<p>CISA released six Industrial Control Systems (ICS) advisories on December 20, 2022. These advisories provide timely information about current security issues, vulnerabilities, and exploits surrounding ICS.</p>|Tuesday, December 20, 2022|
 |[Samba Releases Security Updates](https://www.cisa.gov/uscert/ncas/current-activity/2022/12/16/samba-releases-security-updates)|<p>The Samba Team has released security updates to address vulnerabilities in multiple versions of Samba. An attacker could exploit some of these vulnerabilities to take control of an affected system. </p>|Friday, December 16, 2022|
 
 ---

## OBS-Vigilance [:arrow_heading_up:](#cyberowl)

 |Title|Description|Date|
 |---|---|---|
 |[<a href="https://vigilance.fr/vulnerability/Smarty-Cross-Site-Scripting-via-function-mailto-php-40228" class="noirorange"><b>Smarty</b>: Cross Site Scripting via function.mailto.php</a>](https://vigilance.fr/vulnerability/Smarty-Cross-Site-Scripting-via-function-mailto-php-40228)|An attacker can trigger a Cross Site Scripting of Smarty, via |Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/Linux-kernel-reuse-after-free-via-get-vaddr-frames-40227" class="noirorange"><b>Linux kernel</b>: reuse after free via get_vaddr_frames()</a>](https://vigilance.fr/vulnerability/Linux-kernel-reuse-after-free-via-get-vaddr-frames-40227)|An attacker can force the reuse of a freed memory area of the Linux kernel, via get_vaddr_frames(), in order to trigger a denial of service, and possibly to run code...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/PHP-SQL-injection-via-PDO-quote-40226" class="noirorange"><b>PHP</b>: SQL injection via PDO::quote()</a>](https://vigilance.fr/vulnerability/PHP-SQL-injection-via-PDO-quote-40226)|An attacker can use a SQL injection of PHP, via PDO::quote(), in order to read or alter data...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/Dell-Unisphere-for-PowerMax-three-vulnerabilities-40225" class="noirorange"><b>Dell Unisphere for PowerMax</b>: three vulnerabilities</a>](https://vigilance.fr/vulnerability/Dell-Unisphere-for-PowerMax-three-vulnerabilities-40225)|An attacker can use several vulnerabilities of Dell Unisphere for PowerMax...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/Vim-buffer-overflow-via-msg-puts-printf-40224" class="noirorange"><b>Vim</b>: buffer overflow via msg_puts_printf()</a>](https://vigilance.fr/vulnerability/Vim-buffer-overflow-via-msg-puts-printf-40224)|An attacker can trigger a buffer overflow of Vim, via msg_puts_printf(), in order to trigger a denial of service, and possibly to run code...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/Vim-out-of-bounds-memory-reading-via-Status-Line-Percent-Zero-40223" class="noirorange"><b>Vim</b>: out-of-bounds memory reading via Status Line Percent Zero</a>](https://vigilance.fr/vulnerability/Vim-out-of-bounds-memory-reading-via-Status-Line-Percent-Zero-40223)|An attacker can force a read at an invalid memory address of Vim, via Status Line Percent Zero, in order to trigger a denial of service, or to obtain sensitive information...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/Linux-kernel-buffer-overflow-via-ksmbd-CIFS-ENCPWD-SIZE-40222" class="noirorange"><b>Linux kernel</b>: buffer overflow via ksmbd CIFS_ENCPWD_SIZE</a>](https://vigilance.fr/vulnerability/Linux-kernel-buffer-overflow-via-ksmbd-CIFS-ENCPWD-SIZE-40222)|An attacker can trigger a buffer overflow of the Linux kernel, via ksmbd CIFS_ENCPWD_SIZE, in order to trigger a denial of service, and possibly to run code...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/ReFirm-Labs-binwalk-file-corruption-via-extractor-py-40221" class="noirorange"><b>ReFirm Labs binwalk</b>: file corruption via extractor.py</a>](https://vigilance.fr/vulnerability/ReFirm-Labs-binwalk-file-corruption-via-extractor-py-40221)|An attacker can create a symbolic link, in order to alter the pointed file, with privileges of ReFirm Labs binwalk, via extractor.py...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/Google-Android-Pixel-multiple-vulnerabilities-of-January-2023-40220" class="noirorange"><b>Google Android  Pixel</b>: multiple vulnerabilities of January 2023</a>](https://vigilance.fr/vulnerability/Google-Android-Pixel-multiple-vulnerabilities-of-January-2023-40220)|An attacker can use several vulnerabilities of Google Android  Pixel...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/FortiManager-privilege-escalation-via-Passwordless-Admin-40219" class="noirorange"><b>FortiManager</b>: privilege escalation via Passwordless Admin</a>](https://vigilance.fr/vulnerability/FortiManager-privilege-escalation-via-Passwordless-Admin-40219)|An attacker can bypass restrictions of FortiManager, via Passwordless Admin, in order to escalate his privileges...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/rmt-server-privilege-escalation-via-pubcloud-40218" class="noirorange"><b>rmt-server</b>: privilege escalation via pubcloud</a>](https://vigilance.fr/vulnerability/rmt-server-privilege-escalation-via-pubcloud-40218)|An attacker can bypass restrictions of rmt-server, via pubcloud, in order to escalate his privileges...|Visit link for details|
 
 ---

## VulDB [:arrow_heading_up:](#cyberowl)

 |Title|Description|Date|
 |---|---|---|
 
 ---

## CERT-FR [:arrow_heading_up:](#cyberowl)

 |Title|Description|Date|
 |---|---|---|
 |[Multiples vulnérabilités dans le noyau Linux d’Ubuntu](https://www.cert.ssi.gouv.fr/avis/CERTFR-2023-AVI-0010/)|De multiples vulnérabilités ont été corrigées dans |Publié le 6 janvier 2023|
 |[Multiples vulnérabilités dans PHP](https://www.cert.ssi.gouv.fr/avis/CERTFR-2023-AVI-0009/)|De multiples vulnérabilités ont été découvertes dans PHP. Elles permettent à un attaquant de provoquer un problème de sécurité non spécifié par l'éditeur.|Publié le 6 janvier 2023|
 |[Multiples vulnérabilités dans les produits IBM](https://www.cert.ssi.gouv.fr/avis/CERTFR-2023-AVI-0008/)|De multiples vulnérabilités ont été découvertes dans les produits IBM. Elles permettent à un attaquant de provoquer un déni de service à distance et une atteinte à la confidentialité des données.|Publié le 6 janvier 2023|
 |[Multiples vulnérabilités dans IBM AIX et VIOS](https://www.cert.ssi.gouv.fr/avis/CERTFR-2023-AVI-0007/)|De multiples vulnérabilités ont été découvertes dans IBM AIX et VIOS. Elles permettent à un attaquant de provoquer un déni de service et une élévation de privilèges.|Publié le 5 janvier 2023|
 |[Multiples vulnérabilités dans les produits Symantec](https://www.cert.ssi.gouv.fr/avis/CERTFR-2023-AVI-0006/)|De multiples vulnérabilités ont été découvertes dans les produits Symantec. Elles permettent à un attaquant de provoquer une exécution de code arbitraire à distance, un contournement de la politique de sécurité et une injection de code indirecte à distance (XSS).|Publié le 4 janvier 2023|
 |[Vulnérabilité dans Synology VPN Plus Server](https://www.cert.ssi.gouv.fr/avis/CERTFR-2023-AVI-0005/)|Une vulnérabilité a été découverte dans Synology VPN Plus Server. Elle permet à un attaquant de provoquer une exécution de code arbitraire à distance.|Publié le 4 janvier 2023|
 |[Multiples vulnérabilités dans IBM Sterling Global Mailbox](https://www.cert.ssi.gouv.fr/avis/CERTFR-2023-AVI-0004/)|De multiples vulnérabilités ont été découvertes dans IBM Sterling. Elles permettent à un attaquant de provoquer une exécution de code arbitraire à distance et un contournement de la politique de sécurité.|Publié le 4 janvier 2023|
 |[Multiples vulnérabilités dans les produits Android](https://www.cert.ssi.gouv.fr/avis/CERTFR-2023-AVI-0003/)|De multiples vulnérabilités ont été découvertes dans les produits Android. Certaines d'entre elles permettent à un attaquant de provoquer un problème de sécurité non spécifié par l'éditeur, une exécution de code arbitraire à distance et un déni de service à distance.|Publié le 4 janvier 2023|
 |[Multiples vulnérabilités dans les produits Fortinet](https://www.cert.ssi.gouv.fr/avis/CERTFR-2023-AVI-0002/)|De multiples vulnérabilités ont été corrigées dans |Publié le 4 janvier 2023|
 |[Vulnérabilité dans Apache Tomcat](https://www.cert.ssi.gouv.fr/avis/CERTFR-2023-AVI-0001/)|Une vulnérabilité a été découverte dans Apache Tomcat. Elle permet à un attaquant de provoquer un problème de sécurité non spécifié par l'éditeur.|Publié le 4 janvier 2023|
 
 ---

## MA-CERT [:arrow_heading_up:](#cyberowl)

 |Title|Description|Date|
 |---|---|---|
 |[39650601/23 - Vulnérabilités dans Android](https://www.dgssi.gov.ma//fr/content/3965060123-vulnerabilites-dans-android.html)|Plusieurs vulnérabilités critiques ont été corrigées dans le système d’exploitation Android. L’exploitation de ces vulnérabilités peut permettre à un attaquant de réussir une élévation de privilèges, de causer un déni de service, d’...|06 janvier 2023|
 |[39640501/23 - Vulnérabilité critique affectant Zoho Password Manager Pro](https://www.dgssi.gov.ma//fr/content/3964050123-vulnerabilite-critique-affectant-zoho-password-manager-pro.html)|Zoho a publié un avis de sécurité pour corriger une vulnérabilité critique dans Password Manager Pro. Un attaquant pourrait exploiter cette vulnérabilité afin d’injecter des requêtes SQL personnalisées et d'accéder aux informations...|05 janvier 2023|
 |[39630501/23 - Vulnérabilités dans les produitsFortinet](https://www.dgssi.gov.ma//fr/content/3963050123-vulnerabilites-dans-les-produits-fortinet.html)|Fortinet a publié un avis de sécurité pour corriger plusieurs vulnérabilités dans les produits susmentionnés. L’exploitation de ces failles peut permettre à un attaquant distant d'exécuter du code ou des commandes arbitraires non...|05 janvier 2023|
 |[39620401/23 - Vulnérabilité critique dans Synolgy VPN serveur](https://www.dgssi.gov.ma//fr/content/3962040123-vulnerabilite-critique-dans-synolgy-vpn-serveur.html)|Synology a corrigé une vulnérabilité critique affectant les routeurs configurés pour fonctionner comme des serveurs VPN. L’exploitation de cette faille peut permettre à un attaquant distant d'exécuter du code arbitraire.|04 janvier 2023|
 |[39613012/22 - Vulnérabilité critique dans plusieurs modèles de routeur Wi-Fi NETGEAR](https://www.dgssi.gov.ma//fr/content/3961301222-vulnerabilite-critique-dans-plusieurs-modeles-de-routeur-wi-fi-netgear.html)|Une vulnérabilité critique a été corrigée dans plusieurs modèles de routeur Wi-Fi NET-GEAR. L’exploitation de cette faille peut permettre à un attaquant d’exécuter du code arbitraire à distance et de causer un déni de service.|30 décembre 2022|
 |[39602612/22 - Vulnérabilité critique dans le CMS Ghost ](https://www.dgssi.gov.ma//fr/content/3960261222-vulnerabilite-critique-dans-le-cms-ghost.html)|Une vulnérabilité critique a été corrigée dans le système d'abonnement aux newsletters du CMS Ghost. L'exploitation de cette faille pourrait permettre à des attaquants de créer ou de modifier des newsletters en insérant du code...|26 décembre 2022|
 |[39592012/22 - Vulnérabilité dans Mozilla Thunderbird ](https://www.dgssi.gov.ma//fr/content/3959201222-vulnerabilite-dans-mozilla-thunderbird.html)|Mozilla a publié une mise à jour de sécurité pour corriger une vulnérabilité affectant Mozilla Thunderbird. Un attaquant pourrait exploiter cette faille afin d’exécuter du code arbitraire à distance.|22 décembre 2022|
 |[39602112/22 - Anciennes vulnérabilités des produits Cisco activement exploitées](https://www.dgssi.gov.ma//fr/content/3960211222-anciennes-vulnerabilites-des-produits-cisco-activement-exploitees.html)|Cisco a mis à jour plusieurs avis de sécurité pour signaler l'exploitation active de plusieurs anciennes vulnérabilités affectant ses produits. Les failles, dont certaines sont classées comme critiques, ont un impact sur les systèmes...|21 décembre 2022|
 |[39592012/22 - Vulnérabilités dans Microsoft Edge](https://www.dgssi.gov.ma//fr/content/3959201222-vulnerabilites-dans-microsoft-edge.html)|Microsoft annonce la correction de plusieurs vulnérabilités dans Microsoft Edge. L’exploitation de ces failles peut permettre à un attaquant de porter atteinte à la confidentialité des données.|20 décembre 2022|
 |[39582012/22 - Vulnérabilités dans Foxit Reader et Foxit PDF Editor](https://www.dgssi.gov.ma//fr/content/3958201222-vulnerabilites-dans-foxit-reader-et-foxit-pdf-editor.html)|Foxit annonce la correction de plusieurs vulnérabilités affectant Foxit Reader et Foxit PDF Editor. L’exploitation de ces failles peut permettre à un attaquant d’exécuter du code arbitraire à distance ou de porter atteinte à la...|20 décembre 2022|
 |[39572012/22 - Vulnérabilités dans Citrix Hypervisor](https://www.dgssi.gov.ma//fr/content/3957201222-vulnerabilites-dans-citrix-hypervisor.html)|Citrixannonce la disponibilité d’une mise à jour de sécurité permettant la correction de plusieurs vulnérabilités affectant les versions de Citrix Hypervisor susmentionnées. L’exploitation de ces failles peut permettre à un attaquant de...|20 décembre 2022|
 
 ---

## IBMCLOUD [:arrow_heading_up:](#cyberowl)

 |Title|Description|Date|
 |---|---|---|
 |[Apache James server information disclosure (CVE-2022-45935)](https://exchange.xforce.ibmcloud.com/activity/list?filter=Vulnerabilities)|Visit link for details|Jan 6, 2023|
 |[Zoom Rooms for Windows installers privilege escalation (CVE-2022-36930)](https://exchange.xforce.ibmcloud.com/activity/list?filter=Vulnerabilities)|Visit link for details|Jan 6, 2023|
 |[Zoom Rooms for Windows clients privilege escalation (CVE-2022-36929)](https://exchange.xforce.ibmcloud.com/activity/list?filter=Vulnerabilities)|Visit link for details|Jan 6, 2023|
 |[Zoom for Android clients directory traversal (CVE-2022-36928)](https://exchange.xforce.ibmcloud.com/activity/list?filter=Vulnerabilities)|Visit link for details|Jan 6, 2023|
 |[Zoom Rooms for macOS privilege escalation (CVE-2022-36927)](https://exchange.xforce.ibmcloud.com/activity/list?filter=Vulnerabilities)|Visit link for details|Jan 6, 2023|
 |[Zoom Rooms for macOS privilege escalation (CVE-2022-36926)](https://exchange.xforce.ibmcloud.com/activity/list?filter=Vulnerabilities)|Visit link for details|Jan 6, 2023|
 |[Zoom Rooms for macOS security bypass (CVE-2022-36925)](https://exchange.xforce.ibmcloud.com/activity/list?filter=Vulnerabilities)|Visit link for details|Jan 6, 2023|
 
 ---

## ZeroDayInitiative [:arrow_heading_up:](#cyberowl)

 |Title|Description|Date|
 |---|---|---|
 