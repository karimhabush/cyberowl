
 <div id='top'></div>

# CyberOwl

 > Last Updated 20/11/2022 09:11:22 UTC
 
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
 |[CISA, NSA, and ODNI Release Guidance for Customers on Securing the Software Supply Chain ](https://www.cisa.gov/uscert/ncas/current-activity/2022/11/17/cisa-nsa-and-odni-release-guidance-customers-securing-software)|<p>Today, CISA, the National Security Agency (NSA), and the Office of the Director of National Intelligence (ODNI), published the third of a three-part series on securing the software supply chain: <a href="https://media.defense.gov/2022/Nov/17/2003116445/-1/-1/0/ESF_SECURING_THE_SOFTWARE_SUPPLY_CHAIN_CUSTOMER.PDF">Securing Software Supply Chain Series - Recommended Practices Guide for Customers</a>.</p>|Thursday, November 17, 2022|
 |[#StopRansomware: Hive](https://www.cisa.gov/uscert/ncas/current-activity/2022/11/17/stopransomware-hive)|<p>Today, CISA, the Federal Bureau of Investigation (FBI), and the Department of Health and Human Services (HHS) released joint Cybersecurity Advisory (CSA) <a href="https://www.cisa.gov/uscert/ncas/alerts/aa22-321a">#StopRansomware: Hive Ransomware</a> to provide network defenders tactics, techniques, and procedures (TTPs) and indicators of compromise (IOCs) associated with Hive ransomware variants. FBI investigations identified these TTPs and IOCs as recently as November 2022. </p>|Thursday, November 17, 2022|
 |[CISA Releases Two Industrial Control Systems Advisories](https://www.cisa.gov/uscert/ncas/current-activity/2022/11/17/cisa-releases-two-industrial-control-systems-advisories)|<p>CISA has released two (2) Industrial Control Systems (ICS) advisories on November 17, 2022. These advisories provide timely information about current security issues, vulnerabilities, and exploits surrounding ICS.</p>|Thursday, November 17, 2022|
 |[Cisco Releases Security Updates for Identity Services Engine](https://www.cisa.gov/uscert/ncas/current-activity/2022/11/16/cisco-releases-security-updates-identity-services-engine)|<p>Cisco has released security updates for vulnerabilities affecting Cisco Identity Services Engine (ISE). A remote attacker could exploit some of these vulnerabilities to bypass authorization and access system files. For updates addressing vulnerabilities, see the <a href="https://tools.cisco.com/security/center/publicationListing.x">Cisco Security Advisories page</a>.   </p>|Wednesday, November 16, 2022|
 |[Samba Releases Security Updates](https://www.cisa.gov/uscert/ncas/current-activity/2022/11/16/samba-releases-security-updates)|<p>The Samba Team has released <a href="https://www.samba.org/samba/history/security.html">security updates</a> to address vulnerabilities in multiple versions of Samba. An attacker could exploit some of these vulnerabilities to take control of an affected system.</p>|Wednesday, November 16, 2022|
 |[Mozilla Releases Security Updates for Multiple Products](https://www.cisa.gov/uscert/ncas/current-activity/2022/11/16/mozilla-releases-security-updates-multiple-products)|<p>Mozilla has released security updates to address vulnerabilities in Thunderbird, Firefox ESR, and Firefox. An attacker could exploit these vulnerabilities to cause user confusion or conduct spoofing attacks.</p>|Wednesday, November 16, 2022|
 
 ---

## MA-CERT [:arrow_heading_up:](#cyberowl)

 |Title|Description|Date|
 |---|---|---|
 |[39281711/22 - Vulnérabilités dans les produits F5](https://www.dgssi.gov.ma//fr/content/3928171122-vulnerabilites-dans-les-produits-f5.html)|Deux vulnérabilités ont été corrigées dans les produits F5 susmentionnés. L'exploitation de ces failles permet à un attaquant d’exécuter du code arbitraire à distance, de porter atteinte aux informations confidentielles et de...|17 novembre 2022|
 |[39271711/22 - Vulnérabilité dans Samba](https://www.dgssi.gov.ma//fr/content/3927171122-vulnerabilite-dans-samba.html)|Une vulnérabilité a été corrigée dans Samba, permet à un attaquant d’exécuter des commandes arbitraires à distance, de contourner la politique de sécurité et de causer un déni de service.|17 novembre 2022|
 |[39261711/22 - Vulnérabilités affectant Cisco Identity Services Engine](https://www.dgssi.gov.ma//fr/content/3926171122-vulnerabilites-affectant-cisco-identity-services-engine.html)|Cisco annonce la correction de quatre vulnérabilités affectant certaines versions de son produit Identity Services Engine.L'exploitation de ces vulnérabilités peutpermettreà un attaquant distant d’injecter du contenu dans une...|17 novembre 2022|
 |[39251611/22 - Vulnérabilités dans Mozilla Firefox et Thunderbird ](https://www.dgssi.gov.ma//fr/content/3925161122-vulnerabilites-dans-mozilla-firefox-et-thunderbird.html)|Mozilla a publié des mises à jour de sécurité pour corriger plusieurs vulnérabilités affectant lesproduits susmentionnés. Un attaquant pourrait exploiter certaines de ces vulnérabilités afin d’exécuter du code arbitraire à distance et de...|16 novembre 2022|
 |[39241511/22 - Vulnérabilité dans Sophos UTM](https://www.dgssi.gov.ma//fr/content/3924151122-vulnerabilite-dans-sophos-utm.html)|Une vulnérabilité a été corrigée dans Sophos UTM. L’exploitation de cette faille peut permettre à un attaquant de causer un problème de sécurité non spécifié.|15 novembre 2022|
 |[39221511/22- Vulnérabilités affectantle navigateur Microsoft Edge ](https://www.dgssi.gov.ma//fr/content/3922151122-vulnerabilites-affectant-le-navigateur-microsoft-edge.html)|Microsoft vient de publier une mise à jour de sécurité qui permet de corriger plusieursvulnérabilités affectant le navigateur Microsoft Edge. L’exploitation de ces vulnérabilités peut permettre à un attaquant de provoquer des problèmes...|15 novembre 2022|
 |[39211411/22 - Vulnérabilité dans PaloAlto Cortex XSOAR ](https://www.dgssi.gov.ma//fr/content/3921141122-vulnerabilite-dans-paloalto-cortex-xsoar.html)|Une vulnérabilité a été corrigée dans PaloAlto Cortex XSOAR. L’exploitation de cette faille peut permettre à un attaquant d’exécuter des commandes avec des privilèges élevés.|14 novembre 2022|
 |[39201111/22 - Vulnérabilités affectant plusieurs produits d’Apple ](https://www.dgssi.gov.ma//fr/content/3920111122-vulnerabilites-affectant-plusieurs-produits-d-apple.html)|Apple annonce lacorrectionde deuxvulnérabilitésaffectant ses produits susmentionnés. L’exploitation de ces vulnérabilités peutpermettre à un attaquant distant d’exécuter du code arbitraire ou de causer un déni de service.|11 novembre 2022|
 |[39191011/22 - Vulnérabilités affectant des produitsAMD ](https://www.dgssi.gov.ma//fr/content/3919101122-vulnerabilites-affectant-des-produits-amd.html)|AMD annonce la correction de plusieurs vulnérabilités affectant ses produits susmentionnés. En exploitant ces vulnérabilités, un attaquant peut exécuter du code arbitraire, accéder à des informations confidentielles, élever ses privilèges...|10 novembre 2022|
 |[39181011/22 - Vulnérabilités critiques dans les produits Lenovo](https://www.dgssi.gov.ma//fr/content/3918101122-vulnerabilites-critiques-dans-les-produits-lenovo.html)|Trois vulnérabilités critiques ont été corrigées dans plusieurs produits Lenovo permettant à un attaquant de désactiver UEFI Secure Boot qui garantit qu'aucun code malveillant ne peut être chargé et exécuté pendant le processus de...|10 novembre 2022|
 |[39151011/22 - Vulnérabilités critiques affectant des produits d’Intel](https://www.dgssi.gov.ma//fr/content/3915101122-vulnerabilites-critiques-affectant-des-produits-d-intel.html)|Intel annonce la disponibilité de mises à jour de sécurité qui corrigent des vulnérabilités critiquesaffectant ses produits susmentionnés. L'exploitation de ces vulnérabilités peut permettre à un attaquant d’accéder à des données...|10 novembre 2022|
 
 ---

## CERT-FR [:arrow_heading_up:](#cyberowl)

 |Title|Description|Date|
 |---|---|---|
 |[Multiples vulnérabilités dans le noyau Linux d’Ubuntu](https://www.cert.ssi.gouv.fr/avis/CERTFR-2022-AVI-1039/)|De multiples vulnérabilités ont été corrigées dans |Publié le 17 novembre 2022|
 |[Multiples vulnérabilités dans Cisco Identity Services Engine](https://www.cert.ssi.gouv.fr/avis/CERTFR-2022-AVI-1038/)|De multiples vulnérabilités ont été découvertes dans Cisco Identity Services Engine. Elles permettent à un attaquant de provoquer une exécution de code arbitraire à distance, un contournement de la politique de sécurité et une injection de code indirecte à distance (XSS).|Publié le 17 novembre 2022|
 |[Multiples vulnérabilités dans le noyau Linux de SUSE](https://www.cert.ssi.gouv.fr/avis/CERTFR-2022-AVI-1037/)|De multiples vulnérabilités ont été corrigées dans |Publié le 17 novembre 2022|
 |[Multiples vulnérabilités dans le noyau Linux de Red Hat](https://www.cert.ssi.gouv.fr/avis/CERTFR-2022-AVI-1036/)|De multiples vulnérabilités ont été corrigées dans |Publié le 16 novembre 2022|
 |[Multiples vulnérabilités dans le noyau Linux de SUSE](https://www.cert.ssi.gouv.fr/avis/CERTFR-2022-AVI-1035/)|De multiples vulnérabilités ont été corrigées dans |Publié le 16 novembre 2022|
 |[Vulnérabilité dans Samba](https://www.cert.ssi.gouv.fr/avis/CERTFR-2022-AVI-1034/)|Une vulnérabilité a été découverte dans Samba. Elle permet à un attaquant de provoquer une exécution de code arbitraire à distance, un déni de service à distance et un contournement de la politique de sécurité.|Publié le 16 novembre 2022|
 |[Multiples vulnérabilités dans les produits Mozilla](https://www.cert.ssi.gouv.fr/avis/CERTFR-2022-AVI-1033/)|De multiples vulnérabilités ont été corrigées dans |Publié le 16 novembre 2022|
 |[[SCADA] Vulnérabilité dans Moxa NE-4100T](https://www.cert.ssi.gouv.fr/avis/CERTFR-2022-AVI-1032/)|Une vulnérabilité a été découverte dans Moxa NE-4100T. Elle permet à un attaquant de provoquer un contournement de la politique de sécurité.|Publié le 15 novembre 2022|
 |[Multiples vulnérabilités dans le noyau Linux de SUSE](https://www.cert.ssi.gouv.fr/avis/CERTFR-2022-AVI-1031/)|De multiples vulnérabilités ont été découvertes dans le noyau Linux de SUSE. Certaines d'entre elles permettent à un attaquant de provoquer un problème de sécurité non spécifié par l'éditeur, un déni de service à distance et une atteinte à l'intégrité des données.|Publié le 14 novembre 2022|
 |[Multiples vulnérabilités dans Microsoft Edge](https://www.cert.ssi.gouv.fr/avis/CERTFR-2022-AVI-1030/)|De multiples vulnérabilités ont été corrigées dans |Publié le 14 novembre 2022|
 
 ---

## OBS-Vigilance [:arrow_heading_up:](#cyberowl)

 |Title|Description|Date|
 |---|---|---|
 |[<a href="https://vigilance.fr/vulnerability/Linux-kernel-reuse-after-free-via-read-bbreg-hdl-39940" class="noirorange"><b>Linux kernel</b>: reuse after free via read_bbreg_hdl()</a>](https://vigilance.fr/vulnerability/Linux-kernel-reuse-after-free-via-read-bbreg-hdl-39940)|An attacker can force the reuse of a freed memory area of the Linux kernel, via read_bbreg_hdl(), in order to trigger a denial of service, and possibly to run code...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/FreeRDP-directory-traversal-via-Drive-Channel-39939" class="noirorange"><b>FreeRDP</b>: directory traversal via Drive Channel</a>](https://vigilance.fr/vulnerability/FreeRDP-directory-traversal-via-Drive-Channel-39939)|An attacker can traverse directories of FreeRDP, via Drive Channel, in order to read a file outside the service root path...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/FreeRDP-out-of-bounds-memory-reading-via-Drive-Channel-39938" class="noirorange"><b>FreeRDP</b>: out-of-bounds memory reading via Drive Channel</a>](https://vigilance.fr/vulnerability/FreeRDP-out-of-bounds-memory-reading-via-Drive-Channel-39938)|An attacker can force a read at an invalid memory address of FreeRDP, via Drive Channel, in order to trigger a denial of service, or to obtain sensitive information...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/FreeRDP-five-vulnerabilities-39937" class="noirorange"><b>FreeRDP</b>: five vulnerabilities</a>](https://vigilance.fr/vulnerability/FreeRDP-five-vulnerabilities-39937)|An attacker can use several vulnerabilities of FreeRDP...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/Go-ingress-filtrering-bypass-via-Nul-Set-Environment-Variables-39936" class="noirorange"><b>Go</b>: ingress filtrering bypass via Nul Set Environment Variables</a>](https://vigilance.fr/vulnerability/Go-ingress-filtrering-bypass-via-Nul-Set-Environment-Variables-39936)|An attacker can bypass filtering rules of Go, via Nul Set Environment Variables, in order to send malicious data...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/phpseclib-weak-signature-39935" class="noirorange"><b>phpseclib</b>: weak signature</a>](https://vigilance.fr/vulnerability/phpseclib-weak-signature-39935)|An attacker can use malicious data on phpseclib, in order to deceive the victim...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/Jupyter-Core-code-execution-via-Current-Working-Directory-39934" class="noirorange"><b>Jupyter Core</b>: code execution via Current Working Directory</a>](https://vigilance.fr/vulnerability/Jupyter-Core-code-execution-via-Current-Working-Directory-39934)|An attacker can use a vulnerability of Jupyter Core, via Current Working Directory, in order to run code...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/PJSIP-buffer-overflow-via-pjmedia-rtcp-fb-parse-rpsi-39933" class="noirorange"><b>PJSIP</b>: buffer overflow via <wbr>pjmedia_rtcp_fb_pars<wbr>e_rpsi()</wbr></wbr></a>](https://vigilance.fr/vulnerability/PJSIP-buffer-overflow-via-pjmedia-rtcp-fb-parse-rpsi-39933)|An attacker can trigger a buffer overflow of PJSIP, via |Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/IBM-InfoSphere-DataStage-code-execution-via-Special-Elements-39930" class="noirorange"><b>IBM InfoSphere DataStage</b>: code execution via Special Elements</a>](https://vigilance.fr/vulnerability/IBM-InfoSphere-DataStage-code-execution-via-Special-Elements-39930)|An attacker can use a vulnerability of IBM InfoSphere DataStage, via Special Elements, in order to run code...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/F5-BIG-IP-code-execution-via-Advanced-Shell-39929" class="noirorange"><b>F5 BIG-IP</b>: code execution via Advanced Shell</a>](https://vigilance.fr/vulnerability/F5-BIG-IP-code-execution-via-Advanced-Shell-39929)|An attacker can use a vulnerability of F5 BIG-IP, via Advanced Shell, in order to run code...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/F5-BIG-IP-privilege-escalation-via-iControl-REST-39928" class="noirorange"><b>F5 BIG-IP</b>: privilege escalation via iControl REST</a>](https://vigilance.fr/vulnerability/F5-BIG-IP-privilege-escalation-via-iControl-REST-39928)|An attacker can bypass restrictions of F5 BIG-IP, via iControl REST, in order to escalate his privileges...|Visit link for details|
 
 ---

## VulDB [:arrow_heading_up:](#cyberowl)

 |Title|Description|Date|
 |---|---|---|
 |[librenms cross site scripting](https://vuldb.com/?id.214037)|Visit link for details|2022-11-20 at 08:59|
 |[librenms cross site scripting](https://vuldb.com/?id.214036)|Visit link for details|2022-11-20 at 08:58|
 |[librenms cross site scripting](https://vuldb.com/?id.214035)|Visit link for details|2022-11-20 at 08:57|
 |[librenms cross site scripting](https://vuldb.com/?id.214034)|Visit link for details|2022-11-20 at 08:56|
 |[librenms cross site scripting](https://vuldb.com/?id.214033)|Visit link for details|2022-11-20 at 08:55|
 |[librenms session expiration](https://vuldb.com/?id.214032)|Visit link for details|2022-11-20 at 08:52|
 |[librenms deserialization](https://vuldb.com/?id.214031)|Visit link for details|2022-11-20 at 08:44|
 |[LibreNMS Admin User View cross site scripting](https://vuldb.com/?id.214030)|Visit link for details|2022-11-20 at 08:43|
 |[Trojan.Win32.Platinum.gen WTSAPI32.dll untrusted search path](https://vuldb.com/?id.214029)|Visit link for details|2022-11-20 at 19:41|
 |[davidmoreno onion Log response.c onion_response_flush allocation of resources](https://vuldb.com/?id.214028)|Visit link for details|2022-11-20 at 19:38|
 