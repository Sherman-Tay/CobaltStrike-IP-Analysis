# Automated Analysis of drb-ra CobaltStrike C2 intel feed
## Project Background
[@drb-ra](https://twitter.com/drb_ra) is a reliable automated Cobalt Strike C2 Intelligence Feed that extracts source/raw data based on Censys - https://censys.io/ 

With the objective of active and automated monitoring, I have written a python script that can be run as a cron job to perform daily queries of the new entries added on the feed within a specific country, and perform OSINT analysis to validate if the IP/Domain is **active** and validate if it is a **Cobalt Strike** beacon. A report will be generated and can be sent to an e-mail address for follow-up with the abuse-email address. 

## Understanding DataSet
By default C2s seen active in the last 7 days are added to the main feed files.

  * `C2 IPs` - Live C2 IP (no frontend or CDN IPs - All bad)
  * `C2 Domains` - All domain names extracted from implants, including domain fronting values and fake Host headers (High abuse of MS, Apple and Google).
  * `C2 Domains Filtered` - Excludes several domains abused in domain fronting, along with fake headers for popular sites. Current filter list see:  `exclusions.rex` file
  * `C2 Domains with URL` - Same as domains and domains filtered but including an extra column with the URI path of the C2
  * `C2 Domains with URL and IP` - Same as domains and domains filtered but including an extra column with the URI path of the C2 and another with the C2 IP 

  Additionally a new 30 day set of feed files was added for any C2 seen live in the last 30 days.
  
* VPN 
  * Nord VPN Exit Nodes

* C2_configs 
  * Detailed CobaltStrike Configuration in CSV and JSON including the following fields:  `FirstSeen,ip,ASN,BeaconType,C2Server,Port,SleepTime,Jitter,Proxy_Behavior,HostHeader,CertificateNames,HttpGet_Metadata,HttpPostUri,HttpPost_Metadata,KillDate,PipeName,UserAgent,Watermark,DNS_Idle,DNS_Sleep` IP reflects the true C2 IP not the one provided in the configuration of the beacon.

## Useful Notes
1. It is understood that Censys determines the location of a IP/Domain via geolocation. This may be useful at times but it can be highly inaccurate. In order to get a more accurate IP/Domain location, we should query the internet address registries such as APNIC/ARIN. 
2. In order to determine if the version of Cobalt Strike being used is legitimate (by Red Teamers) or by cracked/known APT actors, we can look at the Watermark and Public Key from the Cobalt Strike configuration. A useful source to monitor for known watermarks is the repository by [Didier Stevens](https://github.com/DidierStevens/DidierStevensSuite/blob/master/1768.json).
3. An additional method to determine if a Server is malicious or not is the JARM fingerprint. JARM is an active Transport Layer Security (TLS) server fingerprinting tool, and useful sources to monitor known Cobalt Strike JARMs is the list curated by [Carbonblack](https://github.com/carbonblack/active_c2_ioc_public/blob/main/cobaltstrike/JARM/jarm_cs_202107_uniq_sorted.txt) and by [360quake](https://github.com/360quake/CobaltStrike-JARM/blob/main/CobaltStrike-JARM.csv)

## What the script does
1. Create the directories {cwd}/IOC_info if it has not been created yet, and {cwd}/IOC_info/{date-of-report yyyy-mm-dd}. Can be commented out if not required.
2. Fetch the latest C2 config file from drb-ra's [github page](https://github.com/drb-ra/C2IntelFeeds/blob/master/C2_configs/cobaltstrike.csv), the latest Watermark and Public Key information from Didier Steven's 1768 project, and the latest JARM information from 360Quake and Carbonblack. 
3. Filter for IP/Domains that have been added within a 24 Hour time frame.
4. Queries the IP Addresses against the RIRs to check for those that belong to the country under monitoring. (for hits, a txt file, whois-{IPaddress}.txt will be created for reference). Duplicate entries will be removed.
5. Flagged IP addresses will be queried on Shodan for analysis. If configuration file is found, the following data will be extracted (Watermark, Port Number, Beacon Type, Last Seen, Certificate, JARM, Public Key). 
6. The extracted data will be cross verified for watermark, public key and JARM.
7. A report will be generated for flagged IP addresses and an e-mail can be configured to be sent, with the attachments of whois and shodan-output as reference.

## How To Use
1. Download the file cobaltstrikec2-analysis.py
2. Manually configure the API_SHODAN, EMAIL_ADDRESS, EMAIL_PASSWORD variables (they can be obtained for free. just create a free gmail/shodan account)
3. Configure the function, send_positive_report and send_nil_report's content to fit your purposes. (msg['From'] and msg['To'] and body)
4. Configure the function checkCountry for your region of interest. 
5. Execute python file.

## Libraries Used
1. ioc_fanger
2. smtplib
3. re
4. json
5. socket
6. email
7. numpy
8. pandas
9. shodan
10. prettytable
11. datetime

## Todo:
Include findings from https://michaelkoczwara.medium.com/cobalt-strike-c2-hunting-with-shodan-c448d501a6e2 to include features like pivoting
