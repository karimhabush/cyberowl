
 <div id='top'></div>

# CyberOwl

 > Last Updated 16/02/2023 15:23:26 UTC
 
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
 |[HK-CERT](#hk-cert-arrow_heading_up)|Hong Kong Computer Emergency Response Team Coordination Centre.|
 |[CA-CCS](#ca-ccs-arrow_heading_up)|Canadian Centre for Cyber Security.|
 |[EU-CERT](#eu-cert-arrow_heading_up)|European Union Agency for Cybersecurity.|
 
 > Suggest a source by opening an [issue](https://github.com/karimhabush/cyberowl/issues)! :raised_hands:

# US-CERT

 |Title|Description|Date|
 |---|---|---|
 |[Adobe Releases Security Updates for Multiple Products](https://www.cisa.gov/uscert/ncas/current-activity/2023/02/14/adobe-releases-security-updates-multiple-products)|<p>Adobe has released security updates to address multiple vulnerabilities in Adobe software. An attacker can exploit these vulnerabilities to take control of an affected system.</p>|Tuesday, February 14, 2023|
 |[Mozilla Releases Security Updates for Firefox 110 and Firefox ESR](https://www.cisa.gov/uscert/ncas/current-activity/2023/02/14/mozilla-releases-security-updates-firefox-110-and-firefox-esr)|<p>Mozilla has released security updates to address vulnerabilities in Firefox 110 and Firefox ESR. An attacker could exploit these vulnerabilities to take control of an affected system.</p>|Tuesday, February 14, 2023|
 |[Citrix Releases Security Updates for Workspace Apps, Virtual Apps and Desktops](https://www.cisa.gov/uscert/ncas/current-activity/2023/02/14/citrix-releases-security-updates-workspace-apps-virtual-apps-and)|<p>Citrix has released security updates to address high-severity vulnerabilities (CVE-2023-24486, CVE-2023-24484, CVE-2023-24485, and CVE-2023-24483) in Citrix Workspace Apps, Virtual Apps and Desktops. A local user could exploit these vulnerabilities to take control of an affected system.</p>|Tuesday, February 14, 2023|
 |[CISA Adds Four Known Exploited Vulnerabilities to Catalog](https://www.cisa.gov/uscert/ncas/current-activity/2023/02/14/cisa-adds-four-known-exploited-vulnerabilities-catalog)|<p>CISA has added four new vulnerabilities to its <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog">Known Exploited Vulnerabilities Catalog</a>, based on evidence of active exploitation. These types of vulnerabilities are frequent attack vectors for malicious cyber actors and pose significant risks to the federal enterprise. <strong>Note</strong>: To view the newly added vulnerabilities in the catalog, click on the arrow in the "Date Added to Catalog" column, which will sort by descending dates.</p>|Tuesday, February 14, 2023|
 |[Microsoft Releases February 2023 Security Updates](https://www.cisa.gov/uscert/ncas/current-activity/2023/02/14/microsoft-releases-february-2023-security-updates)|<p>Microsoft has released updates to address multiple vulnerabilities in Microsoft software. An attacker can exploit some of these vulnerabilities to take control of an affected system.</p>|Tuesday, February 14, 2023|
 |[Apple Releases Security Updates for Multiple Products](https://www.cisa.gov/uscert/ncas/current-activity/2023/02/14/apple-releases-security-updates-multiple-products)|<p>Apple has released security updates to address vulnerabilities in multiple products. An attacker could exploit these vulnerabilities to take control of an affected device.</p>|Tuesday, February 14, 2023|
 

# OBS-Vigilance

 |Title|Description|Date|
 |---|---|---|
 |[<a href="https://vigilance.fr/vulnerability/Go-x-text-language-out-of-bounds-memory-reading-via-BCP-47-Language-Tag-Parsing-40584" class="noirorange"><b>Go x/text/language</b>: out-of-bounds memory reading via BCP 47 Language Tag Parsing</a>](https://vigilance.fr/vulnerability/Go-x-text-language-out-of-bounds-memory-reading-via-BCP-47-Language-Tag-Parsing-40584)|An attacker can force a read at an invalid memory address of Go x/text/language, via BCP 47 Language Tag Parsing, in order to trigger a denial of service, or to obtain sensitive information...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/Linux-kernel-reuse-after-free-via-binder-alloc-c-40583" class="noirorange"><b>Linux kernel</b>: reuse after free via binder_alloc.c</a>](https://vigilance.fr/vulnerability/Linux-kernel-reuse-after-free-via-binder-alloc-c-40583)|An attacker can force the reuse of a freed memory area of the Linux kernel, via binder_alloc.c, in order to trigger a denial of service, and possibly to run code...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/efs-utils-file-read-write-via-Mount-Helper-40582" class="noirorange"><b>efs-utils</b>: file read/write via Mount Helper</a>](https://vigilance.fr/vulnerability/efs-utils-file-read-write-via-Mount-Helper-40582)|An attacker can bypass access restrictions of efs-utils, via Mount Helper, in order to read or alter files...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/pfSense-ingress-filtrering-bypass-via-Anti-brute-Force-40581" class="noirorange"><b>pfSense</b>: ingress filtrering bypass via Anti-brute Force</a>](https://vigilance.fr/vulnerability/pfSense-ingress-filtrering-bypass-via-Anti-brute-Force-40581)|An attacker can bypass filtering rules of pfSense, via Anti-brute Force, in order to send malicious data...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/pfSense-code-execution-via-WebGUI-40580" class="noirorange"><b>pfSense</b>: code execution via WebGUI</a>](https://vigilance.fr/vulnerability/pfSense-code-execution-via-WebGUI-40580)|An attacker can use a vulnerability of pfSense, via WebGUI, in order to run code...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/pfSense-file-creation-via-WebGUI-40579" class="noirorange"><b>pfSense</b>: file creation via WebGUI</a>](https://vigilance.fr/vulnerability/pfSense-file-creation-via-WebGUI-40579)|An attacker can bypass access restrictions of pfSense, via WebGUI, in order to create a file...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/pfSense-Cross-Site-Scripting-via-WebGUI-40578" class="noirorange"><b>pfSense</b>: Cross Site Scripting via WebGUI</a>](https://vigilance.fr/vulnerability/pfSense-Cross-Site-Scripting-via-WebGUI-40578)|An attacker can trigger a Cross Site Scripting of pfSense, via WebGUI, in order to run JavaScript code in the context of the web site...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/pfSense-Cross-Site-Scripting-via-WebGUI-40577" class="noirorange"><b>pfSense</b>: Cross Site Scripting via WebGUI</a>](https://vigilance.fr/vulnerability/pfSense-Cross-Site-Scripting-via-WebGUI-40577)|An attacker can trigger a Cross Site Scripting of pfSense, via WebGUI, in order to run JavaScript code in the context of the web site...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/pfSense-Cross-Site-Scripting-via-WebGUI-40576" class="noirorange"><b>pfSense</b>: Cross Site Scripting via WebGUI</a>](https://vigilance.fr/vulnerability/pfSense-Cross-Site-Scripting-via-WebGUI-40576)|An attacker can trigger a Cross Site Scripting of pfSense, via WebGUI, in order to run JavaScript code in the context of the web site...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/ClamAV-information-disclosure-via-DMG-File-Parser-40575" class="noirorange"><b>ClamAV</b>: information disclosure via DMG File Parser</a>](https://vigilance.fr/vulnerability/ClamAV-information-disclosure-via-DMG-File-Parser-40575)|An attacker can bypass access restrictions to data of ClamAV, via DMG File Parser, in order to read sensitive information...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/ClamAV-code-execution-via-HFS-File-Parser-40574" class="noirorange"><b>ClamAV</b>: code execution via HFS+ File Parser</a>](https://vigilance.fr/vulnerability/ClamAV-code-execution-via-HFS-File-Parser-40574)|An attacker can use a vulnerability of ClamAV, via HFS+ File Parser, in order to run code...|Visit link for details|
 

# EU-CERT

 |Title|Description|Date|
 |---|---|---|
 |[2023-010: Severe Vulnerabilities in Citrix Workspace, Virtual Apps and Desktops](https://cow-www-prod.azurewebsites.net/publications/security-advisories)|On February 14, 2022, Citrix released Security Bulletins regarding severe vulnerabilities affecting its Citrix Workspace, Virtual Apps and Desktops. If exploited, these vulnerabilities could enable attackers to elevate their privileges and take control of the affected system, but they need local access to the target.|Thursday, February 16, 2023 11:00:00 AM CEST|
 

# VulDB

 |Title|Description|Date|
 |---|---|---|
 

# CERT-FR

 |Title|Description|Date|
 |---|---|---|
 |[Multiples vulnérabilités dans les produits Microsoft](https://www.cert.ssi.gouv.fr/avis/CERTFR-2023-AVI-0133/)|De multiples vulnérabilités ont été corrigées dans |Publié le 15 février 2023|
 |[Multiples vulnérabilités dans Microsoft Azure](https://www.cert.ssi.gouv.fr/avis/CERTFR-2023-AVI-0132/)|De multiples vulnérabilités ont été corrigées dans |Publié le 15 février 2023|
 |[Multiples vulnérabilités dans Microsoft .Net](https://www.cert.ssi.gouv.fr/avis/CERTFR-2023-AVI-0131/)|De multiples vulnérabilités ont été corrigées dans |Publié le 15 février 2023|
 |[Multiples vulnérabilités dans Microsoft Windows](https://www.cert.ssi.gouv.fr/avis/CERTFR-2023-AVI-0130/)|De multiples vulnérabilités ont été corrigées dans |Publié le 15 février 2023|
 |[Multiples vulnérabilités dans Microsoft Office](https://www.cert.ssi.gouv.fr/avis/CERTFR-2023-AVI-0129/)|De multiples vulnérabilités ont été corrigées dans |Publié le 15 février 2023|
 |[Multiples vulnérabilités dans les produits IBM](https://www.cert.ssi.gouv.fr/avis/CERTFR-2023-AVI-0128/)|De multiples vulnérabilités ont été corrigées dans les produits |Publié le 15 février 2023|
 |[Multiples vulnérabilités dans les produits Intel](https://www.cert.ssi.gouv.fr/avis/CERTFR-2023-AVI-0127/)|De multiples vulnérabilités ont été corrigées dans |Publié le 15 février 2023|
 |[[SCADA] Multiples vulnérabilités dans les produits Schneider Electric](https://www.cert.ssi.gouv.fr/avis/CERTFR-2023-AVI-0126/)|De multiples vulnérabilités ont été découvertes dans les produits Schneider Electric. Certaines d'entre elles permettent à un attaquant de provoquer une exécution de code arbitraire à distance, un contournement de la politique de sécurité et une atteinte à l'intégrité des données.|Publié le 15 février 2023|
 |[Multiples vulnérabilités dans les produits SAP](https://www.cert.ssi.gouv.fr/avis/CERTFR-2023-AVI-0125/)|De multiples vulnérabilités ont été découvertes dans les produits SAP. Certaines d'entre elles permettent à un attaquant de provoquer une exécution de code arbitraire à distance, un contournement de la politique de sécurité et une atteinte à l'intégrité des données.|Publié le 15 février 2023|
 |[Multiples vulnérabilités dans Mozilla Firefox](https://www.cert.ssi.gouv.fr/avis/CERTFR-2023-AVI-0124/)|De multiples vulnérabilités ont été corrigées dans|Publié le 15 février 2023|
 

# MA-CERT

 |Title|Description|Date|
 |---|---|---|
 |[40371602/23 - Vulnérabilités corrigées dansGitLab](https://www.dgssi.gov.ma//fr/content/4037160223-vulnerabilites-corrigees-dans-gitlab.html)|GitLab annonce la disponibilité de mises à jour permettant de corriger deux vulnérabilités affectant ses produits susmentionnés. L’exploitation de ces vulnérabilités peut permettre à un attaquant distant d’exécuter du code arbitraire ou d’...|16 février 2023|
 |[40361602/23 - Vulnérabilités affectant plusieursproduits deCisco](https://www.dgssi.gov.ma//fr/content/4036160223-vulnerabilites-affectant-plusieurs-produits-de-cisco.html)|Cisco annonce la correction de plusieurs vulnérabilités affectant certaines versions de ses produits susmentionnés.L'exploitation de ces vulnérabilités peutpermettreà un attaquant distant d’accéder à des informations...|16 février 2023|
 |[40351602/23 - Vulnérabilités critiques dans les produits Splunk](https://www.dgssi.gov.ma//fr/content/4035160223-vulnerabilites-critiques-dans-les-produits-splunk.html)|Splunk a publié une mise à jour de sécurité corrigeant plusieurs vulnérabilités critiques dans les produits susmentionnés. L’exploitation de ces vulnérabilités peut permettre à un attaquant d’exécuter du code arbitraire, de contourner la...|16 février 2023|
 |[40341602/23 - Vulnérabilités dansles produits Intel](https://www.dgssi.gov.ma//fr/content/4034160223-vulnerabilites-dans-les-produits-intel.html)|Intel a publié une mise à jour de sécurité corrigeant plusieurs vulnérabilités recensées dans les produits susmentionnés. L’exploitation de ces vulnérabilités peut permettre à un attaquant de porter atteinte à la confidentialité de données...|16 février 2023|
 |[40331602/23 - Vulnérabilités affectant plusieursproduits SAP](https://www.dgssi.gov.ma//fr/content/4033160223-vulnerabilites-affectant-plusieurs-produits-sap.html)|SAP annonce la disponibilité de mises à jour permettant de corriger plusieurs vulnérabilités affectant ses produits susmentionnés. L’exploitation de ces vulnérabilités peut permettre à un attaquant distant d’exécuterdu code arbitraire,...|16 février 2023|
 |[40321502/23 - Fin de support pour Microsoft Exchange Server 2013](https://www.dgssi.gov.ma//fr/content/4032150223-fin-de-support-pour-microsoft-exchange-server-2013.html)|Microsoftannonce la fin du support destiné à Microsoft Exchange Server 2013, et ce à partir du 11 Avril 2023.|15 février 2023|
 |[40261502/23 - « Zero-Day » affectant le navigateur Apple Safari](https://www.dgssi.gov.ma//fr/content/4026150223-zero-day-affectant-le-navigateur-apple-safari.html)|Apple annonce la correction d’une vulnérabilité critique affectant les versions susmentionnées de son navigateur Safari. Selon Apple cette vulnérabilité est activement exploitée et peut permettre à un attaquant distant d’exécuter du code...|15 février 2023|
 |[40251502/23 - Vulnérabilités affectantplusieurs produits de Citrix ](https://www.dgssi.gov.ma//fr/content/4025150223-vulnerabilites-affectant-plusieurs-produits-de-citrix.html)|Citrix annonce la correction de quatre vulnérabilités affectant ses produits susmentionnés.L’exploitation de ces vulnérabilités peut permettre à un utilisateurlocal de contourner les mesures de sécurité et accéder aux systèmes affectés.|15 février 2023|
 |[40311502/23 - Vulnérabilités critiques dans plusieurs produits Microsoft(Patch Tuesday Février 202](https://www.dgssi.gov.ma//fr/content/4031150223-vulnerabilites-critiques-dans-plusieurs-produits-microsoft-patch-tuesday-fevrier-2023.html)|Microsoft annonce la correction de plusieurs vulnérabilités critiques affectant les produits Microsoft susmentionnés. L’exploitation de ces vulnérabilités peut permettre à un attaquant de réussir une élévation de privilèges, d’exécuter du...|15 février 2023|
 |[40301502/23 - Vulnérabilités dans les produits Microsoft Azure (Patch Tuesday Février 2023)](https://www.dgssi.gov.ma//fr/content/4030150223-vulnerabilites-dans-les-produits-microsoft-azure-patch-tuesday-fevrier-2023.html)|Plusieurs vulnérabilités ont été corrigées dans les produits Azure susmentionnés. L’exploitation de ces failles permet à un attaquant de réussir une élévation de privilèges, d’exécuter du code arbitraire et de réussir une usurpation d’...|15 février 2023|
 |[40291502/23 - Vulnérabilités dans Microsoft Exchange Server (Patch Tuesday Février 2023)](https://www.dgssi.gov.ma//fr/content/4029150223-vulnerabilites-dans-microsoft-exchange-server-patch-tuesday-fevrier-2023.html)|Microsoft annonce la correction de plusieurs vulnérabilités affectant les versions susmentionnées de Microsoft Exchange Server. L’exploitation de ces failles peut permettre à un attaquant d’exécuter du code arbitraire.|15 février 2023|
 

# HK-CERT

 |Title|Description|Date|
 |---|---|---|
 |[Git Multiple Vulnerabilities](/security-bulletin/git-multiple-vulnerabilities_20230216)|Multiple vulnerabilities were identified in Git. A remote attacker could exploit some of these vulnerabilities to trigger data manipulation and sensitive information disclosure on the targeted system.|Release Date: 16 Feb 2023|
 |[Splunk Products Multiple Vulnerabilities](/security-bulletin/splunk-products-multiple-vulnerabilities_20230216)|Multiple vulnerabilities were identified in Splunk Products. A remote attacker could exploit some of these vulnerabilities to trigger sensitive information disclosure, data manipulation and cross-site scripting on the targeted system.|Release Date: 16 Feb 2023|
 |[Adobe Monthly Security Update (February 2023)](/security-bulletin/adobe-monthly-security-update-february-2023)|Adobe has released monthly security update for their products: Vulnerable ProductRisk LevelImpactsNotesDetails (including CVE)Adobe After Effects Medium RiskInformation DisclosureRemote Code Execution APSB23-02Adobe Connect Medium RiskSecurity...|Release Date: 15 Feb 2023|
 |[Microsoft Monthly Security Update (February 2023)](/security-bulletin/microsoft-monthly-security-update-february-2023)|Microsoft has released monthly security update for their products: Vulnerable ProductRisk LevelImpactsNotesSQL Server Medium RiskRemote Code ExecutionSpoofing Windows Extremely High RiskRemote Code ExecutionElevation of PrivilegeDenial of Service...|Release Date: 15 Feb 2023|
 |[Mozilla Firefox Multiple Vulnerabilities](/security-bulletin/mozilla-firefox-multiple-vulnerabilities_20230215)|Multiple vulnerabilities were identified in Mozilla Firefox. A remote attacker could exploit some of these vulnerabilities to trigger spoofing, remote code execution, sensitive information disclosure and security restriction bypass on the targeted system.|Release Date: 15 Feb 2023|
 |[Linux Kernel Multiple Vulnerabilities](/security-bulletin/linux-kernel-multiple-vulnerabilities_20230213)|Multiple vulnerabilities were identified in Linux Kernel. A remote attacker could exploit some of these vulnerabilities to trigger denial of service condition, elevation of privilege, remote code execution and sensitive information disclosure on the targeted system. [Updated on 2023-02-15] Updated System...| Release Date: 13 Feb 2023 |
 |[Apple Products Multiple Vulnerabilities](/security-bulletin/apple-products-multiple-vulnerabilities_20230214)|Multiple vulnerabilities were identified in Apple Products. A remote attacker could exploit some of these vulnerabilities to trigger elevation of privilege, remote code execution, sensitive information disclosure on the targeted system. Note:CVE-2023-23529 is being exploited in the wild. [Updated...| Release Date: 14 Feb 2023 |
 |[Microsoft Edge Multiple Vulnerabilities](/security-bulletin/microsoft-edge-multiple-vulnerabilities_20230210)|Multiple vulnerabilities were identified in Microsoft Edge. A remote attacker could exploit some of these vulnerabilities to trigger remote code execution, privilege escalation,  security restriction bypass, denial of service and sensitive information disclosure on the targeted system.|Release Date: 10 Feb 2023|
 |[OpenSSL Multiple Vulnerabilities](/security-bulletin/openssl-multiple-vulnerabilities_20230209)|Multiple vulnerabilities were identified in OpenSSL. A remote attacker could exploit some of these vulnerabilities to trigger denial of service condition, sensitive information disclosure and security restriction bypass on the targeted system.|Release Date: 9 Feb 2023|
 |[Google Chrome Multiple Vulnerabilities](/security-bulletin/google-chrome-multiple-vulnerabilities_20230208)|Multiple vulnerabilities were identified in Google Chrome. A remote attacker could exploit some of these vulnerabilities to trigger remote code execution, privilege escalation,  security restriction bypass, denial of service and sensitive information disclosure on the targeted system.|Release Date: 8 Feb 2023|
 