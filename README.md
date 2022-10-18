
 <div id='top'></div>

# CyberOwl

 > Last Updated 18/10/2022 21:11:17 UTC
 
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
 |[CISA Releases Two Industrial Control Systems Advisories](https://www.cisa.gov/uscert/ncas/current-activity/2022/10/18/cisa-releases-two-industrial-control-systems-advisories)|<p>CISA released two Industrial Control Systems (ICS) advisories on October 18, 2022. These advisories provide timely information about current security issues, vulnerabilities, and exploits surrounding ICS.</p>|Tuesday, October 18, 2022|
 |[CISA Releases RedEye: Red Team Campaign Visualization and Reporting Tool](https://www.cisa.gov/uscert/ncas/current-activity/2022/10/14/cisa-releases-redeye-red-team-campaign-visualization-and-reporting)|<p>CISA has released RedEye, an interactive open-source analytic tool to visualize and report Red Team command and control activities. RedEye allows an operator to quickly assess complex data, evaluate mitigation strategies, and enable effective decision making.</p>|Friday, October 14, 2022|
 |[CISA Releases Twenty-Five Industrial Control Systems Advisories](https://www.cisa.gov/uscert/ncas/current-activity/2022/10/13/cisa-releases-twenty-five-industrial-control-systems-advisories)|<p>CISA has released twenty-five (25) Industrial Control Systems (ICS) advisories on October 13, 2022. These advisories provide timely information about current security issues, vulnerabilities, and exploits surrounding ICS.</p>|Thursday, October 13, 2022|
 |[Adobe Releases Security Updates for Multiple Products](https://www.cisa.gov/uscert/ncas/current-activity/2022/10/11/adobe-releases-security-updates-multiple-products)|<p>Adobe has released security updates to address multiple vulnerabilities in Adobe software. An attacker can exploit some of these vulnerabilities to take control of an affected system.</p>|Tuesday, October 11, 2022|
 |[Microsoft Releases October 2022 Security Updates](https://www.cisa.gov/uscert/ncas/current-activity/2022/10/11/microsoft-releases-october-2022-security-updates)|<p>Microsoft has released updates to address multiple vulnerabilities in Microsoft software. An attacker can exploit some of these vulnerabilities to take control of an affected system.</p>|Tuesday, October 11, 2022|
 |[CISA Has Added One Known Exploited Vulnerability to Catalog](https://www.cisa.gov/uscert/ncas/current-activity/2022/10/11/cisa-has-added-one-known-exploited-vulnerability-catalog)|<p>CISA has added one new vulnerability to its <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog">Known Exploited Vulnerabilities Catalog</a>, based on evidence of active exploitation. This type of vulnerability is a frequent attack vector for malicious cyber actors and pose significant risk to the federal enterprise. Note: To view the newly added vulnerabilities in the catalog, click on the arrow in the "Date Added to Catalog" column, which will sort by descending dates.      </p>|Tuesday, October 11, 2022|
 
 ---

## OBS-Vigilance [:arrow_heading_up:](#cyberowl)

 |Title|Description|Date|
 |---|---|---|
 |[<a href="https://vigilance.fr/vulnerability/Linux-kernel-reuse-after-free-via-io-uring-39607" class="noirorange"><b>Linux kernel</b>: reuse after free via io_uring</a>](https://vigilance.fr/vulnerability/Linux-kernel-reuse-after-free-via-io-uring-39607)|An attacker can force the reuse of a freed memory area of the Linux kernel, via io_uring, in order to trigger a denial of service, and possibly to run code...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/Node-js-xmldom-prototype-pollution-via-copy-39603" class="noirorange"><b>Node.js xmldom</b>: prototype pollution via copy()</a>](https://vigilance.fr/vulnerability/Node-js-xmldom-prototype-pollution-via-copy-39603)|An attacker can alter the JavaScript code of Node.js xmldom, via copy(), in order to change the software behavior...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/FRRouting-reuse-after-free-via-bgp-notify-send-with-data-39602" class="noirorange"><b>FRRouting</b>: reuse after free via <wbr>bgp_notify_send_with<wbr>_data()</wbr></wbr></a>](https://vigilance.fr/vulnerability/FRRouting-reuse-after-free-via-bgp-notify-send-with-data-39602)|An attacker can force the reuse of a freed memory area of FRRouting, via |Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/Mozilla-Firefox-multiple-vulnerabilities-39601" class="noirorange"><b>Mozilla Firefox</b>: multiple vulnerabilities</a>](https://vigilance.fr/vulnerability/Mozilla-Firefox-multiple-vulnerabilities-39601)|An attacker can use several vulnerabilities of Mozilla Firefox...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/OTRS-Help-Desk-information-disclosure-via-Template-Content-39594" class="noirorange"><b>OTRS Help Desk</b>: information disclosure via Template Content</a>](https://vigilance.fr/vulnerability/OTRS-Help-Desk-information-disclosure-via-Template-Content-39594)|An attacker can bypass access restrictions to data of OTRS Help Desk, via Template Content, in order to read sensitive information...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/OTRS-Help-Desk-overload-via-Many-Recipients-Email-39593" class="noirorange"><b>OTRS Help Desk</b>: overload via Many Recipients Email</a>](https://vigilance.fr/vulnerability/OTRS-Help-Desk-overload-via-Many-Recipients-Email-39593)|An attacker can trigger an overload of OTRS Help Desk, via Many Recipients Email, in order to trigger a denial of service...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/Linux-kernel-denial-of-service-via-inet6-stream-ops-39591" class="noirorange"><b>Linux kernel</b>: denial of service via inet6_stream_ops()</a>](https://vigilance.fr/vulnerability/Linux-kernel-denial-of-service-via-inet6-stream-ops-39591)|An attacker can cause a fatal error of the Linux kernel, via inet6_stream_ops(), in order to trigger a denial of service...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/Linux-kernel-denial-of-service-via-tcp-getsockopt-39590" class="noirorange"><b>Linux kernel</b>: denial of service via tcp_getsockopt()</a>](https://vigilance.fr/vulnerability/Linux-kernel-denial-of-service-via-tcp-getsockopt-39590)|An attacker can cause a fatal error of the Linux kernel, via tcp_getsockopt(), in order to trigger a denial of service...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/Linux-kernel-reuse-after-free-via-del-timer-39589" class="noirorange"><b>Linux kernel</b>: reuse after free via del_timer()</a>](https://vigilance.fr/vulnerability/Linux-kernel-reuse-after-free-via-del-timer-39589)|An attacker can force the reuse of a freed memory area of the Linux kernel, via del_timer(), in order to trigger a denial of service, and possibly to run code...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/Linux-kernel-reuse-after-free-via-l2cap-reassemble-sdu-39588" class="noirorange"><b>Linux kernel</b>: reuse after free via <wbr>l2cap_reassemble_sdu<wbr>()</wbr></wbr></a>](https://vigilance.fr/vulnerability/Linux-kernel-reuse-after-free-via-l2cap-reassemble-sdu-39588)|An attacker can force the reuse of a freed memory area of the Linux kernel, via |Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/Exim-reuse-after-free-via-Regex-Variables-39587" class="noirorange"><b>Exim</b>: reuse after free via Regex Variables</a>](https://vigilance.fr/vulnerability/Exim-reuse-after-free-via-Regex-Variables-39587)|An attacker can force the reuse of a freed memory area of Exim, via Regex Variables, in order to trigger a denial of service, and possibly to run code...|Visit link for details|
 
 ---

## VulDB [:arrow_heading_up:](#cyberowl)

 |Title|Description|Date|
 |---|---|---|
 |[Linux Kernel CIFS sess.c sess_free_buffer double free](https://vuldb.com/?id.211364)|Visit link for details|2022-10-18 at 22:06|
 |[Linux Kernel BPF r8152.c intr_callback logging of excessive data](https://vuldb.com/?id.211363)|Visit link for details|2022-10-18 at 22:04|
 |[Linux Kernel iproute2 ipmptcp.c mptcp_limit_get_set memory leak](https://vuldb.com/?id.211362)|Visit link for details|2022-10-18 at 22:01|
 |[Billing System Project editProductImage.php unrestricted upload](https://vuldb.com/?id.211361)|Visit link for details|2022-10-18 at 19:17|
 |[Fortinet FortiTester Certificate Import os command injection](https://vuldb.com/?id.211360)|Visit link for details|2022-10-18 at 19:16|
 |[Fortinet FortiTester Console Login os command injection](https://vuldb.com/?id.211359)|Visit link for details|2022-10-18 at 19:15|
 |[supybot-fedora Refresh resource consumption](https://vuldb.com/?id.211358)|Visit link for details|2022-10-18 at 19:15|
 |[MobSF Mobile Security Framework HTTP Request views.py file inclusion](https://vuldb.com/?id.211357)|Visit link for details|2022-10-18 at 19:10|
 |[TP-LINK AX10v1 hard-coded key](https://vuldb.com/?id.211356)|Visit link for details|2022-10-18 at 19:09|
 |[Tenda AC18 fromSetSysTime stack-based overflow](https://vuldb.com/?id.211355)|Visit link for details|2022-10-18 at 19:08|
 
 ---

## CERT-FR [:arrow_heading_up:](#cyberowl)

 |Title|Description|Date|
 |---|---|---|
 |[Multiples vulnérabilités dans IBM QRadar](https://www.cert.ssi.gouv.fr/avis/CERTFR-2022-AVI-924/)|De multiples vulnérabilités ont été découvertes dans IBM QRadar. Certaines d'entre elles permettent à un attaquant de provoquer une exécution de code arbitraire à distance, un déni de service à distance et une atteinte à l'intégrité des données.|Publié le 18 octobre 2022|
 |[Multiples vulnérabilités dans WordPress](https://www.cert.ssi.gouv.fr/avis/CERTFR-2022-AVI-923/)|De multiples vulnérabilités ont été découvertes dans WordPress. Certaines d'entre elles permettent à un attaquant de provoquer une exécution de code arbitraire à distance, un contournement de la politique de sécurité et une injection de code indirecte à distance (XSS).|Publié le 18 octobre 2022|
 |[Multiples vulnérabilités dans le noyau Linux de SUSE](https://www.cert.ssi.gouv.fr/avis/CERTFR-2022-AVI-922/)|De multiples vulnérabilités ont été corrigées dans |Publié le 17 octobre 2022|
 |[Multiples vulnérabilités dans Microsoft Edge](https://www.cert.ssi.gouv.fr/avis/CERTFR-2022-AVI-921/)|De multiples vulnérabilités ont été découvertes dans Microsoft Edge. Elles permettent à un attaquant de provoquer un problème de sécurité non spécifié par l'éditeur.|Publié le 17 octobre 2022|
 |[Multiples vulnérabilités dans les produits Adobe](https://www.cert.ssi.gouv.fr/avis/CERTFR-2022-AVI-920/)|De multiples vulnérabilités ont été découvertes dans les produits Adobe. Certaines d'entre elles permettent à un attaquant de provoquer une exécution de code arbitraire à distance, un déni de service et un contournement de la politique de sécurité.|Publié le 17 octobre 2022|
 |[Multiples vulnérabilités dans le noyau Linux d’Ubuntu](https://www.cert.ssi.gouv.fr/avis/CERTFR-2022-AVI-919/)|De multiples vulnérabilités ont été découvertes dans le noyau Linux d'Ubuntu. Elles permettent à un attaquant de provoquer une exécution de code arbitraire, un déni de service à distance et une atteinte à la confidentialité des données.|Publié le 14 octobre 2022|
 |[Multiples vulnérabilités dans le noyau Linux de Red Hat](https://www.cert.ssi.gouv.fr/avis/CERTFR-2022-AVI-918/)|De multiples vulnérabilités ont été découvertes dans le noyau Linux de Red Hat. Elles permettent à un attaquant de provoquer un déni de service, une atteinte à la confidentialité des données et une élévation de privilèges.|Publié le 14 octobre 2022|
 |[Multiples vulnérabilités dans Ivanti Connect Secure](https://www.cert.ssi.gouv.fr/avis/CERTFR-2022-AVI-917/)|De multiples vulnérabilités ont été découvertes dans Ivanti Connect Secure. Elles permettent à un attaquant de provoquer un déni de service à distance.|Publié le 14 octobre 2022|
 |[Multiples vulnérabilités dans les produits Juniper](https://www.cert.ssi.gouv.fr/avis/CERTFR-2022-AVI-916/)|De multiples vulnérabilités ont été découvertes dans les produits Juniper. Certaines d'entre elles permettent à un attaquant de provoquer une exécution de code arbitraire à distance, un déni de service à distance et un contournement de la politique de sécurité.|Publié le 13 octobre 2022|
 |[Vulnérabilité dans SonicWall GMS](https://www.cert.ssi.gouv.fr/avis/CERTFR-2022-AVI-915/)|Une vulnérabilité a été découverte dans SonicWall GMS. Elle permet à un attaquant de provoquer un contournement de la politique de sécurité.|Publié le 13 octobre 2022|
 
 ---

## MA-CERT [:arrow_heading_up:](#cyberowl)

 |Title|Description|Date|
 |---|---|---|
 |[38731810/22 - Vulnérabilité critique dans la bibliothèque Apache Commons Text](https://www.dgssi.gov.ma//fr/content/3873181022-vulnerabilite-critique-dans-la-bibliotheque-apache-commons-text.html)|La Fondation Apache Software a publié une mise à jour de sécurité pour corriger une vulnérabilité critique (CVE-2022-42889) dans sa bibliothèque Apache Commons Text.Une exploitation réussie pourrait permettre à un attaquant non...|18 octobre 2022|
 |[38711810/22 - Vulnérabilités affectantle navigateur Microsoft Edge ](https://www.dgssi.gov.ma//fr/content/3871181022-vulnerabilites-affectant-le-navigateur-microsoft-edge.html)|Microsoft vient de publier une mise à jour de sécurité qui permet de corriger plusieursvulnérabilités affectant le navigateur Microsoft Edge. L’exploitation de cette vulnérabilité peut permettre à un attaquant d’exécuter du code...|18 octobre 2022|
 |[38721810/22 - Vulnérabilités dans les produits de vidéoconférence ZOOM ](https://www.dgssi.gov.ma//fr/content/3872181022-vulnerabilites-dans-les-produits-de-videoconference-zoom.html)|Zoom annonce la correction de deux vulnérabilités affectant les produits susmentionnés de vidéoconférence Zoom. L’exploitation de ces failles peut permettre à un attaquant local d’obtenir des informations confidentielles et de prendre le...|18 octobre 2022|
 |[38701710/22 - Vulnérabilités dans les produits Juniper](https://www.dgssi.gov.ma//fr/content/3870171022-vulnerabilites-dans-les-produits-juniper.html)|Juniper annonce la correction de plusieurs vulnérabilités affectant ses produits. L’exploitation de ces failles peut permettre à un attaquant de réussir une élévation de privilèges, d’exécuter du code arbitraire à distance, de causer un...|17 octobre 2022|
 |[38691410/22 - Publication d’exploit de la vulnérabilité « CVE-2022-40684 » affectant les produits Fo](https://www.dgssi.gov.ma//fr/content/3869141022-publication-d-exploit-de-la-vulnerabilite-cve-2022-40684-affectant-les-produits-fortinet.html)|Un code d’exploit est publiquement disponible de la vulnérabilité critique "CVE-2022-40684" de contournement d'authentification affectant les appliances FortiOS, FortiProxy et FortiSwitchManager de Fortinet. Les attaquants...|14 octobre 2022|
 |[38681310/22 - Vulnérabilité dans Palo Alto PAN-OS](https://www.dgssi.gov.ma//fr/content/3868131022-vulnerabilite-dans-palo-alto-pan-os.html)|Une vulnérabilité a été corrigée dans les versions susmentionnées de Palo Alto PAN-OS. L'exploitation de cette faille peut permettre à un attaquant de réussir une usurpation d’identité et une élévation de privilèges.|13 octobre 2022|
 |[38671310/22 - Vulnérabilités critiques affectant Aruba EdgeConnect Enterprise Orchestrator](https://www.dgssi.gov.ma//fr/content/3867131022-vulnerabilites-critiques-affectant-aruba-edgeconnect-enterprise-orchestrator.html)|Aruba Networks annonce la correction detroisvulnérabilités critiques affectant les versions susmentionnées de son produit Aruba EdgeConnect Enterprise Orchestrator. L'exploitation de ces vulnérabilités peutpermettreà un...|13 octobre 2022|
 |[38661310/22 - Vulnérabilités dans Zimbra Collaboration](https://www.dgssi.gov.ma//fr/content/3866131022-vulnerabilites-dans-zimbra-collaboration.html)|Plusieurs vulnérabilités ont été corrigées dans Zimbra Collaboration. L’exploitation de ces failles pourrait permettre à un attaquant d’exécuter du code arbitraireà distance, de réussir une élévation de privilèges et d’injecter du code...|13 octobre 2022|
 |[38661310/22 - Vulnérabilités dans Google Chrome](https://www.dgssi.gov.ma//fr/content/3866131022-vulnerabilites-dans-google-chrome.html)|Google a corrigé plusieurs vulnérabilités dans son navigateur Google Chrome. L’exploitation de ces failles peut permettre à un attaquant de prendre le contrôle du système affecté.|13 octobre 2022|
 |[38661210/22 - Vulnérabilités affectant plusieursproduits SAP](https://www.dgssi.gov.ma//fr/content/3866121022-vulnerabilites-affectant-plusieurs-produits-sap.html)|SAP annonce la disponibilité de mises à jour permettant de corriger plusieurs vulnérabilités affectant ses produits susmentionnés. L’exploitation de ces vulnérabilités peut permettre à un attaquant distant d’exécuterdu code arbitraire, d...|12 octobre 2022|
 |[38651210/22 - Vulnérabilité affectant Apple iOS ](https://www.dgssi.gov.ma//fr/content/3865121022-vulnerabilite-affectant-apple-ios.html)|Apple annonce lacorrectiond’une vulnérabilité affectant son système d’exploitation iOS.L'exploitation decette vulnérabilité peut permettre à un attaquant de causer un déni de service.|12 octobre 2022|
 
 ---

## IBMCLOUD [:arrow_heading_up:](#cyberowl)

 |Title|Description|Date|
 |---|---|---|
 |[IBM WebSphere Application Server spoofing (CVE-2022-38712)](https://exchange.xforce.ibmcloud.com/activity/list?filter=Vulnerabilities)|Visit link for details|Oct 17, 2022|
 |[IBM Business Automation Workflow information disclosure (CVE-2022-35279)](https://exchange.xforce.ibmcloud.com/activity/list?filter=Vulnerabilities)|Visit link for details|Oct 17, 2022|
 |[IBM Cognos Analytics information disclosure (CVE-2022-34339)](https://exchange.xforce.ibmcloud.com/activity/list?filter=Vulnerabilities)|Visit link for details|Oct 17, 2022|
 |[IBM InfoSphere Information Server external entity injection (CVE-2022-40747)](https://exchange.xforce.ibmcloud.com/activity/list?filter=Vulnerabilities)|Visit link for details|Oct 14, 2022|
 |[IBM InfoSphere Information Server denial of service (CVE-2022-40235)](https://exchange.xforce.ibmcloud.com/activity/list?filter=Vulnerabilities)|Visit link for details|Oct 14, 2022|
 |[IBM InfoSphere Information Server command execution (CVE-2022-35717)](https://exchange.xforce.ibmcloud.com/activity/list?filter=Vulnerabilities)|Visit link for details|Oct 14, 2022|
 |[IBM InfoSphere Information Server cross-site scripting (CVE-2022-35642)](https://exchange.xforce.ibmcloud.com/activity/list?filter=Vulnerabilities)|Visit link for details|Oct 14, 2022|
 
 ---

## ZeroDayInitiative [:arrow_heading_up:](#cyberowl)

 |Title|Description|Date|
 |---|---|---|
 |[Microsoft Exchange PowerShell Deserialization of Untrusted Data Remote Code Execution Vulnerability](https://www.zerodayinitiative.com/advisories/ZDI-22-1442/)|Visit link for details|Oct. 17, 2022|
 |[Microsoft Exchange Autodiscover Server-Side Request Forgery Privilege Escalation Vulnerability](https://www.zerodayinitiative.com/advisories/ZDI-22-1441/)|Visit link for details|Oct. 17, 2022|
 |[Siemens Simcenter Femap JT File Parsing Uninitialized Pointer Remote Code Execution Vulnerability](https://www.zerodayinitiative.com/advisories/ZDI-22-1440/)|Visit link for details|Oct. 17, 2022|
 |[Adobe Dimension SKP File Parsing Use-After-Free Remote Code Execution Vulnerability](https://www.zerodayinitiative.com/advisories/ZDI-22-1439/)|Visit link for details|Oct. 14, 2022|
 |[Altair HyperView Player H3D File Parsing Improper Validation of Array Index Remote Code Execution Vulnerability](https://www.zerodayinitiative.com/advisories/ZDI-22-1438/)|Visit link for details|Oct. 14, 2022|
 |[Altair HyperView Player H3D File Parsing Uninitialized Memory Remote Code Execution Vulnerability](https://www.zerodayinitiative.com/advisories/ZDI-22-1437/)|Visit link for details|Oct. 14, 2022|
 |[Altair HyperView Player H3D File Parsing Uninitialized Memory Remote Code Execution Vulnerability](https://www.zerodayinitiative.com/advisories/ZDI-22-1436/)|Visit link for details|Oct. 14, 2022|
 |[Altair HyperView Player H3D File Parsing Memory Corruption Remote Code Execution Vulnerability](https://www.zerodayinitiative.com/advisories/ZDI-22-1435/)|Visit link for details|Oct. 14, 2022|
 