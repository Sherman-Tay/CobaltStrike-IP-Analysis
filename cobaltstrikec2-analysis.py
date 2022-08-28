import ioc_fanger
import os
import time
import socket
import json
import re
import smtplib
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from email.message import EmailMessage
from shodan import Shodan
from prettytable import PrettyTable as pt
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart

#Initialization
API_SHODAN = 'API_KEY_HERE'
api = Shodan(API_SHODAN)
EMAIL_ADDRESS = 'Sender-Email'
EMAIL_PASSWORD = 'Sender-Email-Password'
EMAIL_TO = 'Destination-Email'
COUNTRY_TO_CHECK = "US/CN/JP etc." 
directory = os.getcwd()

def load1768_data():
    # Get from didier stevens suite
    os.system("wget -O 1768.json https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/1768.json")
    with open("{}/1768.json".format(directory), 'r') as f:
        data = json.load(f)
        LastUpdate1768 = data['dLookupValues']['LASTUPDATE']
        Watermark1768 = data['dLookupValues']['37']
        Pubkey1768 = data['dLookupValues']['7']
        f.close()
    return LastUpdate1768, Watermark1768, Pubkey1768


def load_jarm():
    # Get from carbonblack
    os.system("wget -O jarmCB.txt https://raw.githubusercontent.com/carbonblack/active_c2_ioc_public/main/cobaltstrike/JARM/jarm_cs_202107_uniq_sorted.txt")
    with open("{}/jarmCB.txt".format(directory), 'r') as f:
        data = f.read()
        jarmCB = data.split("\n")
        f.close()

    # Get source from 360quake
    os.system("wget -O jarm360.csv https://raw.githubusercontent.com/360quake/CobaltStrike-JARM/main/CobaltStrike-JARM.csv")
    with open("{}/jarm360.csv".format(directory), 'r') as f:
        jarm360 = []
        data = f.read()
        data = data.replace('\n', ',')
        data = data.replace('|||||', ',')
        data = data.split(",")
        for i in data:
            if len(i) > 20:
                jarm360.append(i)
    # Combine sources and remove duplicates
    jarmCombined = jarmCB + list(set(jarm360)-set(jarmCB))
    return jarmCombined

def GetDateString():
    today = datetime.now().astimezone()
    yesterday = today - timedelta(days=1)
    today = today.strftime("%Y-%m-%d")
    yesterday = yesterday.strftime("%Y-%m-%d")
    return today, yesterday


def send_nil_report():
    today, yesterday = GetDateString()
    msg = EmailMessage()
    msg['Subject'] = 'Daily Report on Cobalt Strike C2 Servers - {}'.format(
        today)
    msg['From'] = EMAIL_ADDRESS
    msg['to'] = EMAIL_TO
    msg.set_content('''
Good Afternoon,

We have no hits on Cobalt Strike C2 Servers from our intel sources today.
Thank you.

Regards
	''')

    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
        smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        smtp.send_message(msg)


def send_positive_report(IOC_List, ioc_df):
    today, yesterday = GetDateString()
    directory = os.getcwd()
    ip_addresses = "\n".join(str(e) for e in IOC_List)
    text = '''
Good Afternoon,

C2 Analysis has flagged the following networks found in the Country as command and control server(s) - Cobalt Strike, for malicious activities.

Task: Follow up with the Abuse Teams of the relevant networks to perform any necessary remediation.

The following are the C2 Servers that we have found to be flagged as Cobalt Strike Beacons
{}
{}
The whois records and the shodan output are attached in this email for reference.

Regards
	'''.format(ip_addresses, ioc_df)

    html = """
		<html>
			<head></head>
			<body>
			<p>Good Afternoon,</p>

<p>C2 Analysis has flagged the following networks found in the Country as command and control server(s) - Cobalt Strike, for malicious activities.<p>
<p>Task: Follow up with the Abuse Teams of the relevant networks to perform any necessary remediation.</p>

<p>The following are the C2 Servers that we have found to be flagged as Cobalt Strike Beacons</p>
{}

<p>The whois records and the shodan output are attached in this email for reference.</p>

<p>Regards</p>
		""".format(ioc_df.to_html())

    msg = MIMEMultipart("alternative", None, [
                        MIMEText(text), MIMEText(html, 'html')])
    msg['From'] = EMAIL_ADDRESS
    msg['to'] = EMAIL_TO
    msg['Subject'] = 'Daily Report on Cobalt Strike C2 Servers - {}'.format(
        today)
    msg['Date'] = today
    for filename in os.listdir('{}/IOC_info/{}'.format(directory, today)):
        with open('{}/IOC_info/{}/{}'.format(directory, today, filename), 'rb') as f:
            part = MIMEApplication(
                f.read(),
                Name=os.path.basename(filename))
        part['Content-Disposition'] = 'attachment; filename ="{}"'.format(
            filename)
        msg.attach(part)

    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
        smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        smtp.send_message(msg)


def whois_arin(ip):

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("whois.arin.net", 43))
    s.send(('n ' + ip + '\r\n').encode())

    response = b""

    # setting time limit in seconds
    startTime = time.mktime(datetime.now().timetuple())
    timeLimit = 3
    while True:
        elapsedTime = time.mktime(datetime.now().timetuple()) - startTime
        data = s.recv(4096)
        response += data
        if (not data) or (elapsedTime >= timeLimit):
            break
    s.close()

    print(response.decode())

def whois_apnic(ip):

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("whois.apnic.net", 43))
    s.send((ip + '\r\n').encode())

    response = b""

    # setting time limit in seconds
    startTime = time.mktime(datetime.now().timetuple())
    timeLimit = 3
    while True:
        elapsedTime = time.mktime(datetime.now().timetuple()) - startTime
        data = s.recv(4096)
        response += data
        if (not data) or (elapsedTime >= timeLimit):
            break
    s.close()

    return response.decode()


def checkCountry(data):
    # Checks country of origin. If match, Return TRUE
    if match := re.search('(?<=country:        )[^\n]*', data, re.IGNORECASE):
        country = match.group(0)
    else:
        country = "None"
    if country == COUNTRY_TO_CHECK:
        return True
    else:
        return False


def checkShodan(ip):
    print("Performing Shodan Check for {}".format(ioc_fanger.defang(ip)))
    try:
        Shodan_Flag = None
        host = api.host(ip.strip())
        watermark = None
        port = None
        beacon_type = None
        last_seen = None
        certificate = None
        jarm = None
        public_key = None
        # traverse nested json and save relevant information.
        for item in host['data']:
            if 'cobalt_strike_beacon' in item:
                Shodan_Flag = True
                with open('{}/IOC_info/{}/shodan-{}.txt'.format(directory, today, ip), 'w') as f:
                    f.write(json.dumps(item, indent=4, sort_keys=False))
                    f.close()
                # Extract Port. Check x64 > x86 > None
                if 'x64' not in item['cobalt_strike_beacon']:
                    if item['cobalt_strike_beacon']['x86']['port']:
                        port = item['cobalt_strike_beacon']['x86']['port']
                    else:
                        continue
                else:
                    if item['cobalt_strike_beacon']['x64']['port']:
                        port = item['cobalt_strike_beacon']['x64']['port']
                    elif item['port']:
                        port = item['port']
                    else:
                        continue

                # Extract Watermark
                if 'x64' not in item['cobalt_strike_beacon']:
                    if item['cobalt_strike_beacon']['x86']['watermark']:
                        watermark = str(
                            item['cobalt_strike_beacon']['x86']['watermark'])
                    else:
                        continue
                else:
                    if item['cobalt_strike_beacon']['x64']['watermark']:
                        watermark = str(
                            item['cobalt_strike_beacon']['x64']['watermark'])
                    else:
                        continue

                # Extract Beacon-Type
                if 'x64' not in item['cobalt_strike_beacon']:
                    if item['cobalt_strike_beacon']['x86']['beacon_type']:
                        beacon_type = item['cobalt_strike_beacon']['x86']['beacon_type']
                    else:
                        continue
                else:
                    if item['cobalt_strike_beacon']['x64']['beacon_type']:
                        beacon_type = item['cobalt_strike_beacon']['x64']['beacon_type']
                    else:
                        continue

                # Extract Last_Seen
                if item['timestamp']:
                    last_seen = item['timestamp']
                else:
                    continue

                # Extract JARM
                if 'ssl' in item:
                    if 'jarm' in item['ssl']:
                        jarm = item['ssl']['jarm']
                    else:
                        continue

                    if 'chain' in item['ssl']:
                        certificate = item['ssl']['chain'][0]
                    else:
                        continue
                # Extract PubKey
                    if 'dhparams' in item['ssl']:
                        if public_key in item['ssl']['dhparams']:
                            public_key = str(
                                item['ssl']['dhparams']['public_key'])
                        else:
                            continue
                    else:
                        continue
                # Extract Certificate
        if Shodan_Flag is True:
            print("Active C2 Server found on Shodan")
            return watermark, port, beacon_type, last_seen, certificate, jarm, public_key, Shodan_Flag
        else:
            print("No Active C2 on Shodan")
    except Exception as e:
        print(e)


def remove_duplicates(list):
    res = []
    [res.append(x) for x in list if x not in res]
    return res

if __name__ == "__main__":
  # Create Relevant Folders
  today, yesterday = GetDateString()
  directory = os.getcwd()
  # Create directory for IOC information if does not exist.
  if not os.path.exists("{}/IOC_info".format(directory)):
      os.mkdir("{}/IOC_info".format(directory))
  # Create directory for today's IOC report
  if not os.path.exists("{}/IOC_info/{}".format(directory, today)):
      os.mkdir("{}/IOC_info/{}".format(directory, today))

  # Fetch data 
  os.system("wget -O drbra_source_{}.csv https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/C2_configs/cobaltstrike.csv".format(today))
  LastUpdate1768, Watermark1768, Pubkey1768 = load1768_data()
  jarm_list = load_jarm()

  # Open drb_ra as dataframe and obtain date from 'FirstSeen'.
  # Obtain the relevant rows (24h, today - yesterday)
  df = pd.read_csv("drbra_source_{}.csv".format(today),on_bad_lines='skip')
  df['date'] = df['FirstSeen'].str.extract(r'(\d{2}/\d{2}/\d{4})')
  df['date'] = pd.to_datetime(df['date'])
  mask = (df['date'] > yesterday) & (df['date'] <= today)
  df = df.loc[mask]
  
  # Store IP addresses related to Country.
  country_ip = []

  # APNIC/ARIN whois lookup. Append hits to country_ip
  for ip in df['ip']:
      print("Checking if ip:"+str(ip) + "belongs to the Country")
      #Uncomment the related whois.
      lookup = whois_apnic(ip)
      #lookup = whois_arin(ip)
      if checkCountry(lookup):
          country_ip.append(ip)
          print("hit!")
          # write into whois-<date>.txt
          with open('{}/IOC_info/{}/whois-{}.txt'.format(directory, today, ip), 'w') as f:
              f.write(lookup)
              f.close()

  # Remove duplicates as some entries are just different ports.
  country_ip = remove_duplicates(country_ip)
  # Store IP addresses flagged in analysis.
  IOC_ip = []
  IOC_data = {
      'S/N': [],
      'IP Address': [],
      'Port': [],
      'Jarm': [],
      'Remarks': []
  }
  serial_number = 1

  for ip in country_ip:
      # Shodan Analysis
      watermark, port, beacon_type, last_seen, certificate, jarm, public_key, Shodan_Flag = checkShodan(ip)
      collated_remarks = ""

      if Shodan_Flag:
          print("Need to do something about this ip")
          IOC_ip.append(ioc_fanger.defang(ip))
          # check against 1768
          if str(watermark) in Watermark1768.keys():
              collated_remarks += """Watermark: {} was found. Watermark Info: {}.""".format(
                  watermark, Watermark1768[watermark])
          if public_key in Pubkey1768.keys():
              collated_remarks += "Public key: {} was found with known private key: {}.".format(
                  public_key, Pubkey1768[public_key].values())
          if jarm:
              IOC_data['Jarm'].append(jarm)
              if jarm in jarm_list:
                  collated_remarks += "JARM was found as flagged by OSINT analysis."
          else:
              IOC_data['Jarm'].append("N/A")
          IOC_data['S/N'].append(serial_number)
          IOC_data['IP Address'].append(ioc_fanger.defang(ip))
          IOC_data['Port'].append(port)
          IOC_data['Remarks'].append(collated_remarks)
          serial_number += 1

      else:
          print("IOC was not flagged for this ip")
          # If not on shodan, just remove file of whois as it won't be relevant. 
          os.remove('{}/IOC_info/{}/whois-{}.txt'.format(directory, today, ip))

  print(IOC_data)
  ioc_df = pd.DataFrame(IOC_data)

  # if appended list of IP empty, send nil report, otherwise, compile and send
  if len(ioc_df):
      print("Generate Positive Report")
      send_positive_report(IOC_ip, ioc_df)

  else:
      print("Generate NIL Report...")
      send_nil_report()
