import sys
from flask import Flask
from flask_restful import Resource, Api, reqparse
from flask import request
from flask import json
from flask_cors import CORS, cross_origin
import requests
from flask import Flask, request, jsonify, make_response
import json

app = Flask(__name__)
CORS(app)

baseUrl = "https://XX.XX.XX.XX:8834"

tokenGlobal = ""
idGlobal = ""

@app.route('/signin', methods=['GET', 'POST'])
@cross_origin()
def reviews():
    global tokenGlobal
    global idGlobal
    url = baseUrl + "/session"
    fname =request.json['fname']
    desc = request.json['desc']
    ip = request.json['ip']
    ankur = request.json['ankur']
    email = request.json['email']
    payload = "{\"username\":\"cws-nessus\",\"password\":\"n3$$u$\"}"
    headers = {
        #'Origin': "https://XX.XX.XX.XX:8834",
        'Accept-Encoding': "gzip, deflate",
        'Accept-Language': "en-GB,en-US;q=0.9,en;q=0.8",
        'User-Agent': "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36",
        'Content-Type': "application/json",
        'Accept': "*/*",
        #'Referer': "https://XX.XX.XX.XX:8834/",
        'Connection': "keep-alive",
        'X-API-Token': "990587ED-E2C8-4777-A75A-692153061BDB",
        #'X-API-Token': "C29573E0-EB66-4ABE-8B78-A35B6E96DF37",
        'cache-control': "no-cache",
        #'Postman-Token': "bfec4f1b-b353-4983-ad2d-2c121153b549"
    }

    response = requests.request("POST", url, data=payload, headers=headers, verify=False)
    tokenGlobal = response.json()["token"]
    return createScan(fname, desc, ip, email, ankur)

def createScan(name, desc, targets, email, ankur):
    global tokenGlobal
    global idGlobal
    url = baseUrl + "/scans"

    #payload = "{\"uuid\":\"731a8e52-3ea6-a291-ec0a-d2ff0619c19d7bd788d6be818b65\",\"credentials\":{\"add\":{},\"edit\":{},\"delete\":[]},\"settings\":{\"patch_audit_over_rexec\":\"no\",\"patch_audit_over_rsh\":\"no\",\"patch_audit_over_telnet\":\"no\",\"additional_snmp_port3\":\"161\",\"additional_snmp_port2\":\"161\",\"additional_snmp_port1\":\"161\",\"snmp_port\":\"161\",\"http_login_auth_regex_nocase\":\"no\",\"http_login_auth_regex_on_headers\":\"no\",\"http_login_invert_auth_regex\":\"no\",\"http_login_max_redir\":\"0\",\"http_reauth_delay\":\"\",\"http_login_method\":\"POST\",\"enable_admin_shares\":\"no\",\"start_remote_registry\":\"no\",\"dont_use_ntlmv1\":\"yes\",\"never_send_win_creds_in_the_clear\":\"yes\",\"attempt_least_privilege\":\"no\",\"ssh_client_banner\":\"OpenSSH_5.0\",\"ssh_port\":\"22\",\"ssh_known_hosts\":\"\",\"enable_plugin_debugging\":\"no\",\"log_whole_attack\":\"no\",\"max_simult_tcp_sessions_per_scan\":\"\",\"max_simult_tcp_sessions_per_host\":\"\",\"max_hosts_per_scan\":\"30\",\"max_checks_per_host\":\"5\",\"network_receive_timeout\":\"5\",\"reduce_connections_on_congestion\":\"no\",\"slice_network_addresses\":\"no\",\"stop_scan_on_disconnect\":\"no\",\"safe_checks\":\"yes\",\"advanced_mode\":\"Default\",\"display_unreachable_hosts\":\"no\",\"log_live_hosts\":\"no\",\"reverse_lookup\":\"no\",\"allow_post_scan_editing\":\"yes\",\"silent_dependencies\":\"yes\",\"report_superseded_patches\":\"yes\",\"report_verbosity\":\"Normal\",\"enum_local_users_end_uid\":\"1200\",\"enum_local_users_start_uid\":\"1000\",\"enum_domain_users_end_uid\":\"1200\",\"enum_domain_users_start_uid\":\"1000\",\"request_windows_domain_info\":\"yes\",\"scan_webapps\":\"no\",\"test_default_oracle_accounts\":\"no\",\"provided_creds_only\":\"yes\",\"thorough_tests\":\"no\",\"report_paranoia\":\"Normal\",\"assessment_mode\":\"default\",\"detect_ssl\":\"yes\",\"check_crl\":\"no\",\"enumerate_all_ciphers\":\"yes\",\"cert_expiry_warning_days\":\"60\",\"ssl_prob_ports\":\"Known SSL ports\",\"svc_detection_on_all_ports\":\"yes\",\"udp_scanner\":\"no\",\"syn_scanner\":\"yes\",\"syn_firewall_detection\":\"Automatic (normal)\",\"verify_open_ports\":\"no\",\"only_portscan_if_enum_failed\":\"yes\",\"snmp_scanner\":\"yes\",\"wmi_netstat_scanner\":\"yes\",\"ssh_netstat_scanner\":\"yes\",\"portscan_range\":\"default\",\"unscanned_closed\":\"no\",\"wol_wait_time\":\"5\",\"wol_mac_addresses\":\"\",\"scan_netware_hosts\":\"no\",\"scan_network_printers\":\"no\",\"ping_the_remote_host\":\"yes\",\"udp_ping\":\"no\",\"icmp_ping\":\"yes\",\"icmp_ping_retries\":\"2\",\"icmp_unreach_means_host_down\":\"no\",\"tcp_ping\":\"yes\",\"tcp_ping_dest_ports\":\"built-in\",\"arp_ping\":\"yes\",\"fast_network_discovery\":\"no\",\"test_local_nessus_host\":\"yes\",\"discovery_mode\":\"Port scan (common ports)\",\"attach_report\":\"no\",\"emails\":\"\",\"filter_type\":\"and\",\"filters\":[],\"launch_now\":false,\"enabled\":false,\"file_targets\":\"\",\"text_targets\":\""+ str(targets) +"\",\"scanner_id\":\"1\",\"folder_id\":3,\"description\":\""+ str(desc) +"\",\"name\":\""+str(name)+"\"}}"
    payload = "{\"uuid\":\"731a8e52-3ea6-a291-ec0a-d2ff0619c19d7bd788d6be818b65\",\"credentials\":{\"add\":{},\"edit\":{},\"delete\":[]},\"settings\":{\"patch_audit_over_rexec\":\"no\",\"patch_audit_over_rsh\":\"no\",\"patch_audit_over_telnet\":\"no\",\"additional_snmp_port3\":\"161\",\"additional_snmp_port2\":\"161\",\"additional_snmp_port1\":\"161\",\"snmp_port\":\"161\",\"http_login_auth_regex_nocase\":\"no\",\"http_login_auth_regex_on_headers\":\"no\",\"http_login_invert_auth_regex\":\"no\",\"http_login_max_redir\":\"0\",\"http_reauth_delay\":\"\",\"http_login_method\":\"POST\",\"enable_admin_shares\":\"no\",\"start_remote_registry\":\"no\",\"dont_use_ntlmv1\":\"yes\",\"never_send_win_creds_in_the_clear\":\"yes\",\"attempt_least_privilege\":\"no\",\"ssh_client_banner\":\"OpenSSH_5.0\",\"ssh_port\":\"22\",\"ssh_known_hosts\":\"\",\"enable_plugin_debugging\":\"no\",\"log_whole_attack\":\"no\",\"max_simult_tcp_sessions_per_scan\":\"\",\"max_simult_tcp_sessions_per_host\":\"\",\"max_hosts_per_scan\":\"30\",\"max_checks_per_host\":\"5\",\"network_receive_timeout\":\"5\",\"reduce_connections_on_congestion\":\"no\",\"slice_network_addresses\":\"no\",\"stop_scan_on_disconnect\":\"no\",\"safe_checks\":\"yes\",\"advanced_mode\":\"Default\",\"display_unreachable_hosts\":\"no\",\"log_live_hosts\":\"no\",\"reverse_lookup\":\"no\",\"allow_post_scan_editing\":\"yes\",\"silent_dependencies\":\"yes\",\"report_superseded_patches\":\"yes\",\"report_verbosity\":\"Normal\",\"enum_local_users_end_uid\":\"1200\",\"enum_local_users_start_uid\":\"1000\",\"enum_domain_users_end_uid\":\"1200\",\"enum_domain_users_start_uid\":\"1000\",\"request_windows_domain_info\":\"yes\",\"scan_webapps\":\"no\",\"test_default_oracle_accounts\":\"no\",\"provided_creds_only\":\"yes\",\"thorough_tests\":\"no\",\"report_paranoia\":\"Normal\",\"assessment_mode\":\"default\",\"detect_ssl\":\"yes\",\"check_crl\":\"no\",\"enumerate_all_ciphers\":\"yes\",\"cert_expiry_warning_days\":\"60\",\"ssl_prob_ports\":\"Known SSL ports\",\"svc_detection_on_all_ports\":\"yes\",\"udp_scanner\":\"no\",\"syn_scanner\":\"yes\",\"syn_firewall_detection\":\"Automatic (normal)\",\"verify_open_ports\":\"no\",\"only_portscan_if_enum_failed\":\"yes\",\"snmp_scanner\":\"yes\",\"wmi_netstat_scanner\":\"yes\",\"ssh_netstat_scanner\":\"yes\",\"portscan_range\":\"default\",\"unscanned_closed\":\"no\",\"wol_wait_time\":\"5\",\"wol_mac_addresses\":\"\",\"scan_netware_hosts\":\"no\",\"scan_network_printers\":\"no\",\"ping_the_remote_host\":\"yes\",\"udp_ping\":\"no\",\"icmp_ping\":\"yes\",\"icmp_ping_retries\":\"2\",\"icmp_unreach_means_host_down\":\"no\",\"tcp_ping\":\"yes\",\"tcp_ping_dest_ports\":\"built-in\",\"arp_ping\":\"yes\",\"fast_network_discovery\":\"no\",\"test_local_nessus_host\":\"yes\",\"discovery_mode\":\"Port scan (common ports)\",\"attach_report\":\"no\",\"emails\":\"\",\"filter_type\":\"and\",\"filters\":[],\"launch\":\"ONETIME\",\"launch_now\":false,\"enabled\":true,\"timezone\":\"India Standard Time\",\"starttime\":\""+ str(ankur) + "T" + str(email) + "00" +"\",\"rrules\":\"FREQ=ONETIME\",\"file_targets\":\"\",\"text_targets\":\""+ str(targets) +"\",\"scanner_id\":\"1\",\"folder_id\":3,\"description\":\""+ str(desc) +"\",\"name\":\""+str(name)+"\"}}"
    headers = {
        #'Origin': "https://XX.XX.XX.XX:8834",
        'Accept-Encoding': "gzip, deflate, br",
        'Accept-Language': "en-GB,en-US;q=0.9,en;q=0.8",
        'User-Agent': "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36",
        'X-Cookie': "token=" + str(tokenGlobal),
        'Content-Type': "application/json",
        'Accept': "*/*",
        #'Referer': "https://XX.XX.XX.XX:8834/",
        'Connection': "keep-alive",
        'X-API-Token': "990587ED-E2C8-4777-A75A-692153061BDB",
        #'X-API-Token': "C29573E0-EB66-4ABE-8B78-A35B6E96DF37",
        'cache-control': "no-cache",
        #'Postman-Token': "d025374f-29ca-45da-85e3-cc5e762ff4d9"
    }

    response = requests.request("POST", url, data=payload, headers=headers, verify=False)
    idGlobal = response.json()["scan"]["id"]
    if (str(email) == ""):
        return startScan()


def startScan():
    global tokenGlobal
    global idGlobal

    url = baseUrl + "/scans/"+str(idGlobal)+"/launch"

    headers = {
        #'Origin': "https://XX.XX.XX.XX:8834",
        'Accept-Encoding': "gzip, deflate, br",
        'Accept-Language': "en-GB,en-US;q=0.9,en;q=0.8",
        'User-Agent': "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36",
        'X-Cookie': "token=" + str(tokenGlobal),
        'Content-Type': "application/json",
        'Accept': "*/*",
        #'Referer': "https://XX.XX.XX.XX:8834/",
        'Connection': "keep-alive",
        'Content-Length': "0",
        'X-API-Token': "990587ED-E2C8-4777-A75A-692153061BDB",
        #'X-API-Token': "C29573E0-EB66-4ABE-8B78-A35B6E96DF37",
        'cache-control': "no-cache",
        'Postman-Token': "ec2a71ca-6bb9-43c0-87e6-b41dccdfc707"
    }

    response = requests.request("POST", url, headers=headers, verify=False)

    return response.text

@app.route('/stopScan', methods=['GET', 'POST'])
@cross_origin()
def stopScan():
    global tokenGlobal
    global idGlobal
    if tokenGlobal == "":
        return "Session Timeout"

    if idGlobal == "":
        return "Start scan first"

    url = baseUrl + "/scans/"+str(idGlobal)+"/stop"

    headers = {
        #'Origin': "https://XX.XX.XX.XX:8834",
        'Accept-Encoding': "gzip, deflate, br",
        'Accept-Language': "en-GB,en-US;q=0.9,en;q=0.8",
        'User-Agent': "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36",
        'X-Cookie': "token=" + str(tokenGlobal),
        'Content-Type': "application/json",
        'Accept': "*/*",
        #'Referer': "https://XX.XX.XX.XX:8834/",
        'Connection': "keep-alive",
        'Content-Length': "0",
        'X-API-Token': "990587ED-E2C8-4777-A75A-692153061BDB",
        #'X-API-Token': "C29573E0-EB66-4ABE-8B78-A35B6E96DF37",
        'cache-control': "no-cache",
        'Postman-Token': "ec2a71ca-6bb9-43c0-87e6-b41dccdfc707"
    }

    response = requests.request("POST", url, headers=headers, verify=False)

    return response.text

@app.route('/check', methods=['GET', 'POST'])
@cross_origin()
def check():
    return "working"


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8025, threaded=True)
