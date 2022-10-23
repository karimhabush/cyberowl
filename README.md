
 <div id='top'></div>

# CyberOwl

 > Last Updated 23/10/2022 09:16:20 UTC
 
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
 |[#StopRansomware: Daixin Team](https://www.cisa.gov/uscert/ncas/current-activity/2022/10/21/stopransomware-daixin-team)|<p>CISA, the Federal Bureau of Investigation (FBI), and the Department of Health and Human Services (HHS) have released a joint Cybersecurity Advisory (CSA), #StopRansomware: Daixin Team to provide information on the “Daixin Team,” a cybercrime group actively targeting U.S. businesses, predominantly in the Healthcare and Public Health (HPH) Sector, with ransomware and data extortion operations. This joint CSA provides Daixin actors’ tactics, techniques, and procedures (TTPs) and indicators of compromise (IOCs) obtained from FBI threat response activities and third-party reporting.</p>|Friday, October 21, 2022|
 |[Cisco Releases Security Update for Cisco Identity Services Engine ](https://www.cisa.gov/uscert/ncas/current-activity/2022/10/21/cisco-releases-security-update-cisco-identity-services-engine)|<p>Cisco has released a security update to address vulnerabilities affecting Cisco Identity Services Engine (ISE). A remote attacker could exploit some of these vulnerabilities to take control of an affected system. For updates addressing high and low severity vulnerabilities, see the <a href="https://tools.cisco.com/security/center/publicationListing.x">Cisco Security Advisories page</a>. </p>|Friday, October 21, 2022|
 |[CISA Adds Two Known Exploited Vulnerabilities to Catalog   ](https://www.cisa.gov/uscert/ncas/current-activity/2022/10/20/cisa-adds-two-known-exploited-vulnerabilities-catalog)|<p>CISA has added two vulnerabilities to its <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog">Known Exploited Vulnerabilities Catalog</a>, based on evidence of active exploitation. These types of vulnerabilities are a frequent attack vector for malicious cyber actors and pose significant risk to the federal enterprise. Note: to view the newly added vulnerabilities in the catalog, click on the arrow in the "Date Added to Catalog" column, which will sort by descending dates.      </p>|Thursday, October 20, 2022|
 |[CISA Releases Three Industrial Control Systems Advisories](https://www.cisa.gov/uscert/ncas/current-activity/2022/10/20/cisa-releases-three-industrial-control-systems-advisories)|<p>CISA has released three (3) Industrial Control Systems (ICS) advisories on October 20, 2022. These advisories provide timely information about current security issues, vulnerabilities, and exploits surrounding ICS.</p>|Thursday, October 20, 2022|
 |[Mozilla Releases Security Updates for Firefox](https://www.cisa.gov/uscert/ncas/current-activity/2022/10/20/mozilla-releases-security-updates-firefox)|<p>Mozilla has released security updates to address vulnerabilities in Firefox ESR and Firefox. An attacker could exploit these vulnerabilities to cause denial-of-service conditions.</p>|Thursday, October 20, 2022|
 |[CISA Requests for Comment on Microsoft 365 Security Configuration Baselines](https://www.cisa.gov/uscert/ncas/current-activity/2022/10/20/cisa-requests-comment-microsoft-365-security-configuration)|<p>CISA has issued requests for comment (RFCs) on eight Microsoft 365 security configuration baselines as part of the Secure Cloud Business Application (SCuBA) project to secure federal civilian executive branch agencies’ (FCEB) cloud environments. The baselines:<br>•    Build on and integrate previous security configuration baselines developed by the <a href="https://www.cio.gov/">Federal Chief Information Officers Council’s Cyber Innovation Tiger Team (CITT).</a><br>•    Initiate a series of pilot efforts to advance cloud security practices across the FCEB. </p>|Thursday, October 20, 2022|
 
 ---

## OBS-Vigilance [:arrow_heading_up:](#cyberowl)

 |Title|Description|Date|
 |---|---|---|
 |[<a href="https://vigilance.fr/vulnerability/LibTIFF-buffer-overflow-via-tiffcrop-39684" class="noirorange"><b>LibTIFF</b>: buffer overflow via tiffcrop</a>](https://vigilance.fr/vulnerability/LibTIFF-buffer-overflow-via-tiffcrop-39684)|An attacker can trigger a buffer overflow of LibTIFF, via tiffcrop, in order to trigger a denial of service, and possibly to run code...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/LibTIFF-buffer-overflow-via-TIFFmemcpy-39683" class="noirorange"><b>LibTIFF</b>: buffer overflow via _TIFFmemcpy()</a>](https://vigilance.fr/vulnerability/LibTIFF-buffer-overflow-via-TIFFmemcpy-39683)|An attacker can trigger a buffer overflow of LibTIFF, via _TIFFmemcpy(), in order to trigger a denial of service, and possibly to run code...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/LibTIFF-out-of-bounds-memory-reading-via-writeSingleSection-39682" class="noirorange"><b>LibTIFF</b>: out-of-bounds memory reading via <wbr>writeSingleSection()</wbr></a>](https://vigilance.fr/vulnerability/LibTIFF-out-of-bounds-memory-reading-via-writeSingleSection-39682)|An attacker can force a read at an invalid memory address of LibTIFF, via |Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/LibTIFF-buffer-overflow-via-tiffcrop-TIFFmemset-39681" class="noirorange"><b>LibTIFF</b>: buffer overflow via tiffcrop _TIFFmemset()</a>](https://vigilance.fr/vulnerability/LibTIFF-buffer-overflow-via-tiffcrop-TIFFmemset-39681)|An attacker can trigger a buffer overflow of LibTIFF, via tiffcrop _TIFFmemset(), in order to trigger a denial of service, and possibly to run code...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/LibTIFF-buffer-overflow-via-tiffcrop-extractContigSamplesShifted24bits-39680" class="noirorange"><b>LibTIFF</b>: buffer overflow via tiffcrop <wbr>extractContigSamples<wbr>Shifted24bits()</wbr></wbr></a>](https://vigilance.fr/vulnerability/LibTIFF-buffer-overflow-via-tiffcrop-extractContigSamplesShifted24bits-39680)|An attacker can trigger a buffer overflow of LibTIFF, via tiffcrop |Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/Linux-kernel-memory-corruption-via-follow-page-pte-39679" class="noirorange"><b>Linux kernel</b>: memory corruption via follow_page_pte()</a>](https://vigilance.fr/vulnerability/Linux-kernel-memory-corruption-via-follow-page-pte-39679)|An attacker can trigger a memory corruption of the Linux kernel, via follow_page_pte(), in order to trigger a denial of service, and possibly to run code...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/Linux-kernel-NULL-pointer-dereference-via-nilfs-bmap-lookup-at-level-39678" class="noirorange"><b>Linux kernel</b>: NULL pointer dereference via <wbr>nilfs_bmap_lookup_at<wbr>_level()</wbr></wbr></a>](https://vigilance.fr/vulnerability/Linux-kernel-NULL-pointer-dereference-via-nilfs-bmap-lookup-at-level-39678)|An attacker can force a NULL pointer to be dereferenced on the Linux kernel, via |Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/Exim-reuse-after-free-via-dmarc-dns-lookup-39677" class="noirorange"><b>Exim</b>: reuse after free via dmarc_dns_lookup()</a>](https://vigilance.fr/vulnerability/Exim-reuse-after-free-via-dmarc-dns-lookup-39677)|An attacker can force the reuse of a freed memory area of Exim, via dmarc_dns_lookup(), in order to trigger a denial of service, and possibly to run code...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/Linux-kernel-buffer-overflow-via-bigben-probe-39676" class="noirorange"><b>Linux kernel</b>: buffer overflow via bigben_probe()</a>](https://vigilance.fr/vulnerability/Linux-kernel-buffer-overflow-via-bigben-probe-39676)|An attacker can trigger a buffer overflow of the Linux kernel, via bigben_probe(), in order to trigger a denial of service, and possibly to run code...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/Linux-kernel-memory-leak-via-pvr-probe-39675" class="noirorange"><b>Linux kernel</b>: memory leak via pvr_probe()</a>](https://vigilance.fr/vulnerability/Linux-kernel-memory-leak-via-pvr-probe-39675)|An attacker can create a memory leak of the Linux kernel, via pvr_probe(), in order to trigger a denial of service...|Visit link for details|
 |[<a href="https://vigilance.fr/vulnerability/Linux-kernel-memory-leak-via-vhci-write-39674" class="noirorange"><b>Linux kernel</b>: memory leak via vhci_write()</a>](https://vigilance.fr/vulnerability/Linux-kernel-memory-leak-via-vhci-write-39674)|An attacker can create a memory leak of the Linux kernel, via vhci_write(), in order to trigger a denial of service...|Visit link for details|
 
 ---

## VulDB [:arrow_heading_up:](#cyberowl)

 |Title|Description|Date|
 |---|---|---|
 |[Backdoor.Win32.Delf.arh FTP Server missing authentication](https://vuldb.com/?id.212013)|Visit link for details|2022-10-23 at 08:20|
 |[Backdoor.Win32.Psychward.10 Service Port 13013 backdoor](https://vuldb.com/?id.212012)|Visit link for details|2022-10-23 at 08:19|
 |[Email-Worm.Win32.Kipis.c Service Port 8297 backdoor](https://vuldb.com/?id.212011)|Visit link for details|2022-10-23 at 08:18|
 |[Axiomatic Bento4 mp42hevc WriteSample heap-based overflow](https://vuldb.com/?id.212010)|Visit link for details|2022-10-23 at 15:09|
 |[Axiomatic Bento4 mp4edit Create memory leak](https://vuldb.com/?id.212009)|Visit link for details|2022-10-23 at 15:07|
 |[Axiomatic Bento4 mp4edit CreateAtomFromStream memory leak](https://vuldb.com/?id.212008)|Visit link for details|2022-10-23 at 15:05|
 |[Axiomatic Bento4 mp42aac Ap4ByteStream.cpp WritePartial heap-based overflow](https://vuldb.com/?id.212007)|Visit link for details|2022-10-23 at 09:53|
 |[Axiomatic Bento4 mp42ts Ap4LinearReader.cpp Advance use after free](https://vuldb.com/?id.212006)|Visit link for details|2022-10-23 at 09:46|
 |[Axiomatic Bento4 avcinfo AvcInfo.cpp heap-based overflow](https://vuldb.com/?id.212005)|Visit link for details|2022-10-23 at 09:44|
 |[Axiomatic Bento4 avcinfo Ap4BitStream.cpp WriteBytes heap-based overflow](https://vuldb.com/?id.212004)|Visit link for details|2022-10-23 at 09:43|
 
 ---

## CERT-FR [:arrow_heading_up:](#cyberowl)

 |Title|Description|Date|
 |---|---|---|
 |[Multiples vulnérabilités dans le noyau Linux de SUSE](https://www.cert.ssi.gouv.fr/avis/CERTFR-2022-AVI-942/)|De multiples vulnérabilités ont été corrigées dans |Publié le 21 octobre 2022|
 |[Multiples vulnérabilités dans le noyau Linux de Debian](https://www.cert.ssi.gouv.fr/avis/CERTFR-2022-AVI-941/)|De multiples vulnérabilités ont été découvertes dans le noyau Linux de Debian. Certaines d'entre elles permettent à un attaquant de provoquer une exécution de code arbitraire, un déni de service et une atteinte à la confidentialité des données.|Publié le 21 octobre 2022|
 |[Multiples vulnérabilités dans le noyau Linux d’Ubuntu](https://www.cert.ssi.gouv.fr/avis/CERTFR-2022-AVI-940/)|De multiples vulnérabilités ont été corrigées dans |Publié le 21 octobre 2022|
 |[Multiples vulnérabilités dans les produits SolarWinds](https://www.cert.ssi.gouv.fr/avis/CERTFR-2022-AVI-939/)|De multiples vulnérabilités ont été découvertes dans les produits SolarWinds. Elles permettent à un attaquant de provoquer un problème de sécurité non spécifié par l'éditeur et une exécution de code arbitraire à distance.|Publié le 20 octobre 2022|
 |[Multiples vulnérabilités dans les produits Cisco](https://www.cert.ssi.gouv.fr/avis/CERTFR-2022-AVI-938/)|De multiples vulnérabilités ont été découvertes dans les produits Cisco. Elles permettent à un attaquant de provoquer un déni de service à distance, une atteinte à l'intégrité des données et une atteinte à la confidentialité des données.|Publié le 20 octobre 2022|
 |[Multiples vulnérabilités dans les produits F5](https://www.cert.ssi.gouv.fr/avis/CERTFR-2022-AVI-937/)|De multiples vulnérabilités ont été découvertes dans les produits F5. Certaines d'entre elles permettent à un attaquant de provoquer une exécution de code arbitraire à distance, un déni de service à distance et une atteinte à l'intégrité des données.|Publié le 20 octobre 2022|
 |[Vulnérabilité dans OwnCloud](https://www.cert.ssi.gouv.fr/avis/CERTFR-2022-AVI-936/)|Une vulnérabilité a été découverte dans OwnCloud. Elle permet à un attaquant de provoquer un contournement de la politique de sécurité.|Publié le 20 octobre 2022|
 |[Multiples vulnérabilités dans Oracle WebLogic Server](https://www.cert.ssi.gouv.fr/avis/CERTFR-2022-AVI-935/)|De multiples vulnérabilités ont été découvertes dans Oracle WebLogic Server. Certaines d'entre elles permettent à un attaquant de provoquer un problème de sécurité non spécifié par l'éditeur, un déni de service à distance et une atteinte à l'intégrité des données.|Publié le 19 octobre 2022|
 |[Multiples vulnérabilités dans Oracle Virtualization](https://www.cert.ssi.gouv.fr/avis/CERTFR-2022-AVI-934/)|De multiples vulnérabilités ont été découvertes dans Oracle Virtualization. Certaines d'entre elles permettent à un attaquant de provoquer un problème de sécurité non spécifié par l'éditeur, un déni de service à distance et une atteinte à l'intégrité des données.|Publié le 19 octobre 2022|
 |[Multiples vulnérabilités dans Oracle Systems](https://www.cert.ssi.gouv.fr/avis/CERTFR-2022-AVI-933/)|De multiples vulnérabilités ont été découvertes dans Oracle Systems. Certaines d'entre elles permettent à un attaquant de provoquer un problème de sécurité non spécifié par l'éditeur, un déni de service à distance et une atteinte à l'intégrité des données.|Publié le 19 octobre 2022|
 
 ---

## MA-CERT [:arrow_heading_up:](#cyberowl)

 |Title|Description|Date|
 |---|---|---|
 |[38812110/22 - Vulnérabilités dans les produits SolarWinds](https://www.dgssi.gov.ma//fr/content/3881211022-vulnerabilites-dans-les-produits-solarwinds.html)|Plusieurs vulnérabilités ont été corrigées dans les produits SolarWinds susmentionnés. L'exploitation de ces failles pourrait permettre à un attaquant d’exécuter du code arbitraire à distance.|21 octobre 2022|
 |[38802110/22 - Vulnérabilités dans les produits Cisco](https://www.dgssi.gov.ma//fr/content/3880211022-vulnerabilites-dans-les-produits-cisco.html)|Plusieurs vulnérabilités ont été corrigées dans les produits Cisco susmentionnés. L’exploitation de ces failles peut permettre à un attaquant de causer un déni de service et de porter atteinte à la confidentialité des données.|21 octobre 2022|
 |[38792010/22 - Vulnérabilités dans les produits F5](https://www.dgssi.gov.ma//fr/content/3879201022-vulnerabilites-dans-les-produits-f5.html)|Deux vulnérabilités ont été corrigées dans les produits F5 susmentionnés. L’exploitation de ces failles permet à un attaquant distant de causer un déni de service et de porter atteinte à la confidentialité des données.|20 octobre 2022|
 |[38782010/22 - Vulnérabilité dans Avira Security pour Windows](https://www.dgssi.gov.ma//fr/content/3878201022-vulnerabilite-dans-avira-security-pour-windows.html)|Une vulnérabilité a été corrigée dans la fonctionnalité Software Updater d'Avira Security pour Windows. Un attaquant distant pourrait exploiter cette faille afin de réussir une élévation de privilèges.|20 octobre 2022|
 |[38761910/22 - Vulnérabilités affectantle navigateur Mozilla Firefox](https://www.dgssi.gov.ma//fr/content/3876191022-vulnerabilites-affectant-le-navigateur-mozilla-firefox.html-0)|Mozilla Foundation annonce la disponibilité d’une mise à jour de sécurité permettant la correction de plusieurs vulnérabilités au niveau du navigateur Mozilla Firefox. L’exploitation de cesvulnérabilités peut permettre à un...|19 octobre 2022|
 |[38771910/22 - Vulnérabilités dans Adobe Ilustrator ](https://www.dgssi.gov.ma//fr/content/3877191022-vulnerabilites-dans-adobe-ilustrator.html)|Deux vulnérabilités ont été corrigées dans les produits Adobe Illustrator susmentionnés. Un attaquant distant pourrait exploiter certaines de ces vulnérabilités afin d’exécuter du code arbitraire à distance.|19 octobre 2022|
 |[38761910/22 - Vulnérabilités affectantle navigateur Mozilla Firefox](https://www.dgssi.gov.ma//fr/content/3876191022-vulnerabilites-affectant-le-navigateur-mozilla-firefox.html)|Mozilla Foundation annonce la disponibilité d’une mise à jour de sécurité permettant la correction de plusieurs vulnérabilités au niveau du navigateur Mozilla Firefox. L’exploitation de cesvulnérabilités peut permettre à un...|19 octobre 2022|
 |[38751910/22 - "Oracle Critical Patch Update" du Mois Octobre 2022](https://www.dgssi.gov.ma//fr/content/3875191022-oracle-critical-patch-update-du-mois-octobre-2022.html)|Oracle a publié des correctifs de sécurité pour traiter plusieurs vulnérabilités dans le cadre de sa mise à jour « Oracle Critical Patch Update » du mois Octobre 2022. L'exploitation de certaines de ces vulnérabilités pourrait...|19 octobre 2022|
 |[38741910/22 - Vulnérabilités dans le CMS WordPress](https://www.dgssi.gov.ma//fr/content/3874191022-vulnerabilites-dans-le-cms-wordpress.html)|Plusieurs vulnérabilités ont été corrigées dans le CMS WordPress. L’exploitation de ces vulnérabilités peut permettre à un attaquant d’exécuter du code arbitraire à distance, de porter atteinte à l'intégrité des données et de réussir...|19 octobre 2022|
 |[38731810/22 - Vulnérabilité critique dans la bibliothèque Apache Commons Text](https://www.dgssi.gov.ma//fr/content/3873181022-vulnerabilite-critique-dans-la-bibliotheque-apache-commons-text.html)|La Fondation Apache Software a publié une mise à jour de sécurité pour corriger une vulnérabilité critique (CVE-2022-42889) dans sa bibliothèque Apache Commons Text.Une exploitation réussie pourrait permettre à un attaquant non...|18 octobre 2022|
 |[38711810/22 - Vulnérabilités affectantle navigateur Microsoft Edge ](https://www.dgssi.gov.ma//fr/content/3871181022-vulnerabilites-affectant-le-navigateur-microsoft-edge.html)|Microsoft vient de publier une mise à jour de sécurité qui permet de corriger plusieursvulnérabilités affectant le navigateur Microsoft Edge. L’exploitation de cette vulnérabilité peut permettre à un attaquant d’exécuter du code...|18 octobre 2022|
 
 ---

## IBMCLOUD [:arrow_heading_up:](#cyberowl)

 |Title|Description|Date|
 |---|---|---|
 |[Oracle VM VirtualBox denial of service (CVE-2022-21627)](https://exchange.xforce.ibmcloud.com/activity/list?filter=Vulnerabilities)|Visit link for details|Oct 19, 2022|
 |[Oracle VM VirtualBox denial of service (CVE-2022-21621)](https://exchange.xforce.ibmcloud.com/activity/list?filter=Vulnerabilities)|Visit link for details|Oct 19, 2022|
 |[Oracle VM VirtualBox unspecified (CVE-2022-21620)](https://exchange.xforce.ibmcloud.com/activity/list?filter=Vulnerabilities)|Visit link for details|Oct 19, 2022|
 |[Oracle Java SE and Oracle GraalVM Enterprise Edition denial of service (CVE-2022-21626)](https://exchange.xforce.ibmcloud.com/activity/list?filter=Vulnerabilities)|Visit link for details|Oct 19, 2022|
 |[F5OS directory traversal (CVE-2022-41780)](https://exchange.xforce.ibmcloud.com/activity/list?filter=Vulnerabilities)|Visit link for details|Oct 19, 2022|
 |[Oracle VM VirtualBox unspecified (CVE-2022-39427)](https://exchange.xforce.ibmcloud.com/activity/list?filter=Vulnerabilities)|Visit link for details|Oct 19, 2022|
 |[Oracle VM VirtualBox unspecified (CVE-2022-39426)](https://exchange.xforce.ibmcloud.com/activity/list?filter=Vulnerabilities)|Visit link for details|Oct 19, 2022|
 
 ---

## ZeroDayInitiative [:arrow_heading_up:](#cyberowl)

 |Title|Description|Date|
 |---|---|---|
 |[(Pwn2Own) Linux Kernel io_uring Improper Update of Reference Count Privilege Escalation Vulnerability](https://www.zerodayinitiative.com/advisories/ZDI-22-1462/)|Visit link for details|Oct. 21, 2022|
 |[SolarWinds Network Performance Monitor MessageToBytes Deserialization of Untrusted Data Remote Code Execution Vulnerability](https://www.zerodayinitiative.com/advisories/ZDI-22-1461/)|Visit link for details|Oct. 21, 2022|
 |[SolarWinds Network Performance Monitor PropertyBagJsonConverter Deserialization of Untrusted Data Remote Code Execution Vulnerability](https://www.zerodayinitiative.com/advisories/ZDI-22-1460/)|Visit link for details|Oct. 21, 2022|
 |[SolarWinds Network Performance Monitor DeserializeFromStrippedXml Deserialization of Untrusted Data Remote Code Execution Vulnerability](https://www.zerodayinitiative.com/advisories/ZDI-22-1459/)|Visit link for details|Oct. 21, 2022|
 |[GNU Gzip zgrep Argument Injection Remote Code Execution Vulnerability](https://www.zerodayinitiative.com/advisories/ZDI-22-1458/)|Visit link for details|Oct. 21, 2022|
 |[Linux Kernel nftables Uninitialized Variable Information Disclosure Vulnerability](https://www.zerodayinitiative.com/advisories/ZDI-22-1457/)|Visit link for details|Oct. 21, 2022|
 |[LibreOffice Exposed Dangerous Function Remote Code Execution Vulnerability](https://www.zerodayinitiative.com/advisories/ZDI-22-1456/)|Visit link for details|Oct. 21, 2022|
 |[(Pwn2Own) Kepware KEPServerEX Stack-based Buffer Overflow Remote Code Execution Vulnerability](https://www.zerodayinitiative.com/advisories/ZDI-22-1455/)|Visit link for details|Oct. 21, 2022|
 