import nmap

def avail_host (ip):

    nm=nmap.PortScanner()
    print("Searching For Live Host.......")
    nm.scan(hosts=ip, arguments='-sn')
    live_host=[]
    for host in nm.all_hosts():
        if nm[host].state() == "up" :
            live_host.append(host)

    if not live_host:
       print("No Live Host Found")
    else:
      print("Live Host Found:")        
      for live in live_host:
         print(live)

def port_scanning (ip):
    nm=nmap.PortScanner()
    print("Searching For Ports.......")
    nm.scan(ip,'1-1024')

    for host in nm.all_hosts():
        print(f"Host : {host}")
        print(f"State : {nm[host].state()}")
        if nm[host].all_protocols():
         for proto in nm[host].all_protocols():
             print(f"Protocola : {proto}  {nm[host][proto].keys()}")
        else :
            print("Ports Details Not Available")  

def os_scanning(ip):
    nm=nmap.PortScanner()
    print("Detecting OS Info......")
    nm.scan(hosts=ip, arguments='-O --osscan-guess')

    for host in nm.all_hosts():
        print(f"Host : {host}")
        print(f"State : {nm[host].state()}")

        if 'osmatch' in nm[host]:
            if nm[host]['osmatch']:
              for os in nm[host]['osmatch']: 
                 print(f"OS Name : {os['name']}")
                 print(f"Accuracy : {os['accuracy']}%")    
                 print(f"OS Type: {os.get('osclass', [{}])[0].get('type', 'Unknown')}\n") 

            else :
                print("OS Details Not Found")     

        else :
            print("No OS Detection Not Available")   

def route_tracer(ip):
    nm=nmap.PortScanner()
    print("Tracing Route")
    nm.scan(hosts=ip, arguments='-Pn --traceroute ')

    for host in nm.all_hosts():
        print(f"Host : {host}")
        print(f"State : {nm[host].state()}")

        if 'trace'in nm[host]:
            trace =nm[host]['trace']
            for hop in trace:
              hop_ip = trace[hop]['ipaddr']
              hop_rtt = trace[hop]['rtt']
              print(f"IP : {hop_ip}     RTT : {hop_rtt}\n\n")  

        else:
               print("Trace Not Available")     

 
ip = "1.1.1.1"

route_tracer(ip)