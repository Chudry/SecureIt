import os
import sys
import atexit
import time
import requests
import json
import collections
import traceback
import pdb


class SSLException( Exception ):
    pass


class NessusAPI:

    def __init__( self, url, login='', password='', api_akey='', api_skey='', insecure=False, ca_bundle=''): 
        try:
            self.api_akey = None
            self.api_skey = None
            self.use_api = False
            self.name = ''
            self.policy_name = ''
            self.debug = False
            self.format = ''
            self.format_start = ''
            self.format_end = ''
            self.http_response = ''
            self.plugins = {}
            self.names = {}
            self.files = {}
            self.cisco_offline_configs = ''
            self.permissions = ''
            self.policy_id = ''
            self.policy_object = ''
            self.pref_cgi = ''
            self.pref_paranoid = ''
            self.pref_supplied = ''
            self.pref_thorough = ''
            self.set_safe_checks = ''
            self.pref_verbose = ''
            self.pref_silent_dependencies = ''
            self.res = {}
            self.scan_id = ''
            self.scan_name = ''
            self.scan_template_uuid = ''
            self.scan_uuid = ''
            self.tag_id = ''
            self.tag_name = ''
            self.targets = ''
            self.policy_template_uuid = ''
            self.token = ''
            self.url = url
            self.ver_feed = ''
            self.ver_gui = ''
            self.ver_plugins = ''
            self.ver_svr = ''
            self.ver_web = ''
            self.ca_bundle = ca_bundle
            self.insecure = insecure
            self.auth = []
            self.host_vulns = {}
            self.plugin_output = {}
            self.host_details = {}
            self.host_ids = {}

            if insecure and hasattr(requests, 'packages'):
                requests.packages.urllib3.disable_warnings()

            if (api_akey and api_skey):
                self.api_akey = api_akey
                self.api_skey = api_skey
                self.use_api = True

            else:
                self._login(login, password)
                atexit.register(self.action, action="session", method="delete", retry=False)

            self._get_permissions()
            self._get_scanner_id()


        except:
            print >> sys.stderr, ">>>>>>>> Nessuss Connection Failed <<<<<<<<<", traceback.format_exc()
            sys.exit()



############################ LOGIN  #######################

    def _login(self, login="", password=""):
        if login and password:
            self.auth = [login,password]

        self.action(action="session",
                    method="post",
                    extra={"username": self.auth[0], "password": self.auth[1]},
                    private=True,
                    retry=False)

        try:
            self.token = self.res["token"]

        except KeyError:
            if self.res["error"]:
                print("It looks like you're trying to login into a Nessus 5")
                print("instance. Exiting.")
                sys.exit(0)


################################################################################

    def _get_permissions(self):
        '''
        All development has been conducted using and administrator account which
        had the permissions '128'
        '''
        self.action(action="session", method="get")
        self.permissions = self.res['permissions']


################################################################################

    def _get_scanner_id(self):
        '''
        Pull in information about scanner. The ID is necessary, everything else
        is "nice to have" for debugging.
        '''
        self.action(action="scanners", method="get")

        try:
            for scanner in self.res["scanners"]:
                    if scanner["type"] == "local":
                        self.scanner_id = scanner['id']
                        self.ver_plugins = scanner['loaded_plugin_set']
                        self.ver_gui = scanner['ui_version']
                        self.ver_svr = scanner['engine_version']
                        self.ver_feed = scanner['license']['type']
        except:
            pass


################################################################################

    def action(self, action, method, extra={}, files={}, json_req=True, download=False, private=False, retry=True):
        '''
        Generic actions for REST interface. The json_req may be unneeded, but
        the plugin searching functionality does not use a JSON-esque request.
        This is a backup setting to be able to change content types on the fly.
        '''
        payload = {}
        payload.update(extra)
        if self.use_api:
            headers = {'X-ApiKeys': 'accessKey=' + self.api_akey +
                       '; secretKey=' + self.api_skey}
        else:
            headers = {'X-Cookie': 'token=' + str(self.token)}

        if json_req:
            headers.update({'Content-type': 'application/json',
                            'Accept': 'text/plain'})
            payload = json.dumps(payload)

        url = "%s/%s" % (self.url, action)
        if self.debug:
            if private:
                print("JSON    : **JSON request hidden**")
            else:
                print("JSON    :")
                print(payload)

            print("HEADERS :")
            print(headers)
            print("URL     : %s " % url)
            print("METHOD  : %s" % method)
            print("\n")

        # Figure out if we should verify SSL connection (possibly with a user
        # supplied CA bundle). Default to true.
        if self.insecure:
            verify = False
        elif self.ca_bundle:
            verify = self.ca_bundle
        else:
            verify = True

        try:
            req = requests.request(method, url, data=payload, files=files,
                                   verify=verify, headers=headers)

            if not download and req.text:
                self.res = req.json()
            elif not req.text:
                self.res = {}

            if req.status_code != 200:
                print("*****************START ERROR*****************")
                if private:
                    print("JSON    : **JSON request hidden**")
                else:
                    print("JSON    :")
                    print(payload)
                    print(files)

                print("HEADERS :")
                print(headers)
                print("URL     : %s " % url)
                print("METHOD  : %s" % method)
                print("RESPONSE: %d" % req.status_code)
                print("\n")
                self.pretty_print()
                print("******************END ERROR******************")

            if self.debug:
                # This could also contain "pretty_print()" but it makes a lot of
                # noise if enabled for the entire scan.
                print("RESPONSE CODE: %d" % req.status_code)

            if download:
                return req.text
        except requests.exceptions.SSLError as ssl_error:
            raise SSLException('%s for %s.' % (ssl_error, url))
        except requests.exceptions.ConnectionError:
            raise Exception("Could not connect to %s.\nExiting!\n" % url)

        if self.res and "error" in self.res and retry:
            if self.res["error"] == "You need to log in to perform this request":
                self._login()
                self.action(action=action, method=method, extra=extra, files=files, json_req=json_req, download=download, private=private, retry=False)


##############################################]Policies CLIENT API [################################################

    def get_policies_list( self ):
        '''
        Get existing policies list.
        '''
        self.action(action="policies", method="get")

        return self.res[ 'policies' ]


###############################################################################

# Get list of Available Policy Templates

    def get_policy_templates( self ):
        try:
            self.action(action="editor/policy/templates", method="get" )
            return self.res[ 'templates' ]

        except:
            print >> sys.stderr, ">>>>>>>>>>>>>> Unable to obtain policy templates <<<<<<<<<<<<<<<<", traceback.format_exc()


###############################################################################

# Get Policy Template UUID

    def get_policy_template_uuid(self, name):
        '''
        Get the template ID. This provides the default settings for the policy.
        '''
        self.action(action="editor/policy/templates", method="get")
        for template in self.res["templates"]:
            if template["name"] == name:
                return template["uuid"]


###############################################################################

# Set policy edit template

    def set_policy_edit_template(self, uuid):
        '''
        Using the UUID, create the base policy, which will then be manipulated.
        This is easier than attempting to design an entire policy in one call.
        '''
        extra = {"settings": {"name": self.policy_name}, "uuid": uuid}
        self.action(action="policies", method="post", extra=extra)



###############################################################################

# Check if policy exists

    def check_policy_exists(self, name):
        '''
        Set existing policy to use for a scan.
        '''
        policies = self.get_policies_list()

        for policy in policies:
            if policy["name"] == name:
                return True

        return False


################################################################################

# Return policy id by name

    def get_policy_uuid_byname( self, name ):
        '''
        Get Policy ID by name
        '''
        policies = self.get_policies_list()

        for policy in policies:
            if policy["name"] == name:
                return policy[ "template_uuid" ]

        print ">>>>>>>>> Policy not Found <<<<<<<<"
        return False


################################################################################

# Set existing policy to set for Scan

    def policy_set(self, name):
        '''
        Set existing policy to use for a scan.
        '''
        self.policy_name = name
        self.action(action="policies", method="get")

        for policy in self.res["policies"]:
            if policy["name"] == name:
                self.policy_id = policy["id"]
                break

        if not self.policy_id:
            print("no policy with name %s found. Exiting" % name)
            sys.exit(1)

#################################################################################

# Get policy details by ID

    def policy_details(self, policy_id):
        '''
        Retrieves details of an existing policy.
        '''
        self.policy_id = policy_id
        self.action(action="policies/" + str(self.policy_id), method="get")
        return self.res

#################################################################################


# Get Plugins List
    def get_plugin_info( self, plugin ):
        try:
            self.action(action="plugins", method="get" )
            print "\n\n\nPolicy Templates:", self.res

        except:
            print >> sys.stderr, ">>>>>>>>>>>>>> Unable to obtain policy templates <<<<<<<<<<<<<<<<", traceback.format_exc()



#######################################] Scans related Information  [#######################################

# Get list of Scans 

    def get_scans_list( self ):
        try:
            self.action(action="scans", method="get" )
            return self.res[ 'scans' ]

        except:
            print >> sys.stderr, ">>>>>>>>>>>>>> Unable to obtain scans list  <<<<<<<<<<<<<<<<", traceback.format_exc()


#################################################################################

# Get Scan UUID by Name

    def get_scan_ids_byname( self, name ):
        list_scans = self.get_scans_list()
        scan_ids = {}
        for each_scan in list_scans:
            if each_scan[ 'name' ] == name:
                scan_ids[ 'uuid' ] = str( each_scan[ 'uuid' ] )
                scan_ids[ 'id' ] = str( each_scan[ 'id' ] )
                break
        return scan_ids


#################################################################################

# Get Scan Templates

    def get_scan_templates( self ):
        '''
        Get list of all Available templates for Scab
        '''
        self.action( action="editor/scan/templates", method="get")
        return self.res[ 'templates' ]


#################################################################################


# Get Scan Template UUID

    def get_scan_template_uuid(self, name):
        '''
        Get the template ID. This provides the default settings for the policy.
        '''
        self.action(action="editor/scan/templates", method="get")
        for template in self.res["templates"]:
            if template["name"] == name:
                return template[ "uuid" ]
                #self.scan_template_uuid = template["uuid"]


#################################################################################

# Set CLI Scan Tag

    def set_scan_tag(self, name="CLI"):
        '''
        Set the 'tag' for the scan to CLI, if the tag doesn't exist, create it
        and use the resulting ID
        '''
        # Default to "CLI"
        if not self.tag_name:
            self.tag_name = name

        self.action(action="folders", method="get")

        # Get the numeric ID of the tag. This is used to tag where the scan will
        # live in the GUI, as well as help filter the "scan_status" queries and
        # limit traffic/results processing.
        for tag in self.res["folders"]:
            if tag["name"] == self.tag_name:
                self.tag_id = tag["id"]
                break

        # Create the new tag if it doesn't exist
        if not self.tag_id:
            self.action("folders", method="post", extra={"name": self.tag_name})
            self.tag_id = self.res["id"]
                


#################################################################################

# Create a new Scan

    def create_scan( self, targets, name, policy_name="ZeotapTestScan1" ):
        '''
        After building the policy, create a scan.
        '''
        try:
            self.set_scan_tag()
            text_targets = targets.replace(",", "\n")
            self.targets = targets.replace(",", " ")

            scan = { "uuid": self.get_policy_uuid_byname( policy_name ) }
            settings = {}

            # Static items- some could be dynamic, but it's overkill
            settings.update({"launch": "ON_DEMAND"})
            settings.update({"description": "Created with REST API"})
            settings.update({"file_targets": ""})
            settings.update({"filters": []})
            settings.update({"emails": ""})
            settings.update({"filter_type": ""})

            # Dynamic items
            settings.update({"scanner_id": str(self.scanner_id)})
            settings.update({"name": name})
            settings.update({"folder_id": self.tag_id})
            settings.update({"text_targets": text_targets})

            scan.update({"settings": settings})

            self.action(action="scans", method="post", extra=scan)

        except:
            err_msg = "\n>>>>>>>>>>>>>> Scan Creation failed with traceback <<<<<<<<<<<<<<<\n"
            print >> sys.stderr, err_msg, traceback.format_exc() 


#################################################################################

# Check if scan exists by Name

    def scan_exists(self, name):
        '''
        Set existing scan.
        '''
        scan_list = self.get_scans_list()

        if "scans" in self.res and scan_list:
            for scan in scan_list:
                if scan["name"] == name:
                    return True

        return False

#################################################################################

# Update scan Targets

    def scan_update_targets(self, targets, scan_name ):
        '''
        After update targets on existing scan.
        '''
        # This makes the targets much more readable in the GUI, as it splits
        # them out to "one per line"
        text_targets = targets.replace(",", "\n")

        self.targets = targets.replace(",", " ")

        scan_ids = self.get_scan_ids_byname( scan_name )
        scan_id = scan_ids[ 'id' ]
        scan_uuid = scan_ids[ 'uuid' ]

        self.action(action="scans/" + scan_id, method="get")

        scan = {}
        settings = {}

        settings.update({"name": scan_name})
        settings.update({"text_targets": text_targets})
        scan.update({"settings": settings})

        self.action(action="scans/" + scan_id, method="put", extra=scan)

        print >> sys.stdout,"\n>>>>>>>>>>>>>>>>>>> Scan Targets successfully Updated <<<<<<<<<<<<<<<<<<<<<\n"


#################################################################################

# Launch the scan by Name 

    def launch_scan( self, scan_name ):
        '''
        Start the scan and save the UUID to query the status
        '''
        scan_ids = self.get_scan_ids_byname( scan_name )
        scan_id = scan_ids[ 'id' ]
        scan_uuid = scan_ids[ 'uuid' ]
        self.action(action="scans/" + scan_id + "/launch", method="post" )

        print "\n>>>>>>>>>>> Launch Scan Result <<<<<<<<<<<<<\n", self.res


#################################################################################

# Get Scan Details. Note scan details will always fetch latest scan information.
# To obtain old scan execution info, parse the history data.

    def scan_details( self, scan_name ):
        scan_id = self.get_scan_ids_byname( scan_name )[ 'id' ]
        self.action( action="scans/"+scan_id, method="get" )
        return scan_id, self.res


#################################################################################

# Get Scan Execution Status

    def get_scan_execution_status( self, scan_name ):
        scan_id, res = self.scan_details( scan_name )
        return res['info']['status']


#################################################################################

# Get Scan Host's Severity Info

    def get_scan_hosts_severity_info( self, scan_name ):
        try:
            scan_id, scan_details = self.scan_details( scan_name )
            severity_map = { '0': 'Info', '1':'Low', '2':'Medium', '3':'High', '4':'Critical' }
            host_severity_info = {}
            for each_host in scan_details[ 'hosts' ]:
                host_name = each_host['hostname']
                host_severity_info[ host_name ] = {}
                host_severity_info[ host_name ] = {}
                for each_item in each_host['severitycount']['item']:
                    severity_type = severity_map[ str(each_item['severitylevel']) ]
                    host_severity_info[ host_name ][ severity_type ] = each_item['count']

            return host_severity_info
        except:
            print >> sys.stderr, "\n>>>>>>>>>>>>>> Unabel to get Scan host Info <<<<<<<<<<<<<<<<<\n", traceback.format_exc()


#################################################################################

# Get Host Info on give scan

    def get_scanned_hosts_info(self, scan_name):
        scan_id, scan_results = self.scan_details( scan_name )
        hosts_info = {}
        for host in scan_results["hosts"]:
            host_id = host[ 'host_id' ]
            self.action(action="scans/" + scan_id + "/hosts/" + str( host_id), method="get")
            hosts_info[host["hostname"]] = self.res
        return hosts_info

#################################################################################

# Get Host Info By Host ID

    def get_host_info_by_hostid( self, scan_id, host_id ):
        self.action(action="scans/" + scan_id + "/hosts/" + str( host_id), method="get")
        return self.res    


###################################################################################

# Remove Duplicates Hosts
    def _deduplicate_hosts(self, hosts):
        return list({v["hostname"]: v for v in hosts}.values())

###################################################################################

# Download the KnowledgeBase

    def download_kbs( self, scan_name ):
        scan_id = self.get_scan_ids_byname( scan_name )[ 'id' ]
        self.action("scans/" + scan_id, method="get")

        # Merge vulnerability and compliance hosts into a list, unique by
        # hostname.
        merged_hosts = self.res.get("hosts", []) + self.res.get("comphosts", [])
        hosts = self._deduplicate_hosts(hosts=merged_hosts)
        kbs = {}
        for host in hosts:
            kbs[host["hostname"]] = self.action("scans/" + scan_id +
                                                "/hosts/" + str(host["host_id"]) +
                                                "/kb?token=" + str(self.token),
                                                method="get",
                                                download=True )
        return kbs

###################################################################################

# Only use this function in conjunction with "scan_results". Polls every 2 seconds to 
# check status of the scan

    def wait_till_scan_completes( self, scan_name ):
        running = True
        counter = 0
        while running:
            exec_status = self.get_scan_execution_status( scan_name )
            if exec_status == 'completed':
                running = False
            else: #exec_status == 'running':
                time.sleep(2)
                counter += 2
            print ">>>>>>>>> Waiting since %d seconds <<<<<<<<<<" % ( counter )



###################################################################################


    def download_scan(self, scan_name, export_format="nessus"):
        try:
            scan_id = self.get_scan_ids_byname( scan_name )[ 'id' ]


            running = True
            counter = 0

            self.action("scans/" + scan_id, method="get")
            data = {'format': export_format, 'chapters':'vuln_hosts_summary' }
            self.action("scans/" + scan_id + "/export",
                                            method="post",
                                            extra=data)

            file_id = self.res['file']
            print('Download for file id '+str(self.res['file'])+'.')
            while running:
                time.sleep(5)
                counter += 2
                self.action("scans/" + scan_id + "/export/"
                                                + str(file_id) + "/status",
                                                method="get")
                running = self.res['status'] != 'ready'
                sys.stdout.write(".")
                sys.stdout.flush()
                if counter % 60 == 0:
                    print("")

            print("")
            content = self.action("scans/" + scan_id + "/export/"+ str(file_id) + "/download",method="get", download=True)

            return content

        except:
            print >> sys.stderr, "\n>>>>>>>>>>>>>>>>> Downloading Scan Failed <<<<<<<<<<<<<<<<\n", traceback.format_exc()



###################################################################################




if __name__ == '__main__':
    api_akey = "<NessusAPIAccessKey>"
    api_skey = "<NessusAPISecretKey>"
    ness_obj = NessusAPI( url='https://localhost:8834', api_akey=api_akey, api_skey=api_skey , insecure=True )
    print "\n"
    ness_obj.scan_update_targets( "Specify IP Here", scan_name="FirstAutomatedScan" )