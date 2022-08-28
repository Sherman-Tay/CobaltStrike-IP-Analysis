# Automated Analysis of drb-ra C2 intel feed
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
2. In order to determine if the 
