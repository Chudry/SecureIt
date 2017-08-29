import sys, os
import json
import traceback
from utility import Utility
from db import MySQLConnector
from nessrest_api import *
from msf import MetaSploitFrameWork
from db import MySQLConnector
from optparse import OptionParser
import pdb

class AutoSecurity:

	def __init__( self ):		
		print >> sys.stderr, "\n\n\n>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> Security Testing Initiated <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n"
		util_obj = Utility()
		config_file = os.path.join( os.path.dirname(__file__), '../data/config.yaml' )
		self.config_data = util_obj.yaml_read( config_file )		
		self.msf = MetaSploitFrameWork()
		self.nessus = NessusAPI( url=self.config_data[ 'nessus' ][ 'url' ], 
								 api_akey=self.config_data[ 'nessus' ][ 'api_akey' ], 
								 api_skey=self.config_data[ 'nessus' ][ 'api_skey' ], 
								 insecure=True )
		#MySQL DB Connection
		db_host = self.config_data[ 'mysql' ][ 'host' ]
		db_user = self.config_data[ 'mysql' ][ 'user' ]
		db_password = self.config_data[ 'mysql' ][ 'password' ]
		mysql_db = self.config_data[ 'mysql' ][ 'db' ]
		self.db = MySQLConnector( db_host, db_user, db_password, mysql_db )




	def run_security_tests( self, scan_type, scan_name, update_db=True  ):
		try:
			self.msf.setup( self.config_data[ 'metasploit' ][ 'user' ], self.config_data[ 'metasploit' ][ 'password' ] )
			self.console_id = self.msf.create_console()
			
			#Time for NMap to Act
			input_hosts = self.config_data[ 'input_hosts' ]
			self.nmap_action( input_hosts )

			#Extract Hosts with Open ports
			open_port_hosts = self.msf.report_openport_hosts()
			print >> sys.stdout, "\n>>>>>>>>>>>>>>>> OpenPort Hosts <<<<<<<<<<<<<<<<\n", open_port_hosts
			hosts_to_scan = ",".join( open_port_hosts.keys() )

			#Time for Nessus to Act
			hosts_total_scan_info, html_content = self.nessus_action( hosts_to_scan = hosts_to_scan, scan_name=scan_name )
			hosts_total_scan_info[ 'scan_name' ] = scan_name
			hosts_total_scan_info[ 'scan_type' ] = scan_type

			if update_db:
				self.db.update_secutiry_dashboard_tables( open_port_hosts, hosts_total_scan_info )
				report_dir = self.config_data[ 'nessus' ][ 'report_dir' ]
				file_name = scan_type+"_report.html"
				file_path = report_dir+file_name
				print >> sys.stdout, "\n>>>>>>>>>>>> Going to write scan report to : %s <<<<<<<<<<<<<<\n" % ( file_path )
				with open ( file_path, 'w' ) as html_write:
					html_write.write( html_content )

			self.msf.destroy_console( self.console_id )
			

		except:
			err_msg = traceback.format_exc()
			print >> sys.stderr, "\n>>>>>>>>>> Security Test execution failed with traceback <<<<<<<<<<<\n", err_msg




	def nmap_action( self, input_hosts ):
		try:
			#Run 'hosts -d' to clean the Postgres database of Metasploit
			clean_db_command = """
			hosts -d
			"""
			self.msf.command_execution( self.console_id, clean_db_command )		

			#Run Nmap to load the database with Host details
			dbnmap_command = """
			db_nmap -v %s
			""" % ( input_hosts )
			exec_info = self.msf.command_execution( self.console_id, dbnmap_command )
			print >> sys.stdout, "\n~~~~~~~~~~~~~~~~~~~~ NMap Command Execution Info ~~~~~~~~~~~~~~~~~~~~\n", exec_info, "\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"

		except:
			err_msg = traceback.format_exc()
			print >> sys.stderr, "\n>>>>>>>>>> Security Test execution failed with traceback <<<<<<<<<<<", err_msg





	def nessus_action( self, hosts_to_scan='', scan_name='', scan_type='BasicNetworkScan', update_db = False ):
		try:
			print >> sys.stdout, "\n\n\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Going to run Vulenerability Scan for: %s ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n" % ( hosts_to_scan )

			#Update targets and launch BasicNetwork Scan
			if not scan_name:
				scan_name = self.config_data[ 'nessus' ][ 'scans' ][ scan_type ]

			if self.nessus.scan_exists( scan_name ):
				print >> sys.stdout, "\n>>>>>>>>>>>>>>>>>>> Update Scan Targets <<<<<<<<<<<<<<<<<<<<<\n"
				self.nessus.scan_update_targets( hosts_to_scan, scan_name )

				self.nessus.launch_scan( scan_name )

				scan_ids = self.nessus.get_scan_ids_byname( scan_name )

				curr_scan_status = 'running'
				while ( curr_scan_status == 'running' ):
					curr_scan_status = self.nessus.get_scan_execution_status( scan_name )
					if curr_scan_status == 'running':
						time.sleep(300)

				#Set Hosts Total Info to Null
				hosts_total_info = {}
				hosts_total_info[ 'scan_uuid' ] = scan_ids[ 'uuid' ]

				#Get Host Severity Info
				hosts_severity_info = self.nessus.get_scan_hosts_severity_info( scan_name )

				scanned_hosts_info = self.nessus.get_scanned_hosts_info( scan_name )

				for each_host in scanned_hosts_info.keys():
					hosts_total_info[ each_host ] = {}
					hosts_total_info[ each_host ][ 'vulnerabilities' ] = {}
					hosts_total_info[ each_host ][ 'severity' ] = {}
					hosts_total_info[ each_host ][ 'vulnerabilities' ] = scanned_hosts_info[ each_host ][ 'vulnerabilities' ]
					hosts_total_info[ each_host ][ 'severity' ] = hosts_severity_info[ each_host ]


				html_content = self.nessus.download_scan( scan_name, export_format='html' ).encode('utf-8')

				print >> sys.stdout, "\n~~~~~~~~~~~~~~~~~~~~~~~ Vulenerability Scan '%s' is DONE ~~~~~~~~~~~~~~~~~~~~~\n" % ( scan_name )

				return hosts_total_info, html_content

			else:
				raise Exception( ">>>>>>>>>>>>>>>>>>> Scan not Found <<<<<<<<<<<<<<<<<<<<<" )

		except:
			err_msg = traceback.format_exc()
			print >> sys.stderr, ">>>>>>>>>> Nessus Vulenerability scanning failed with traceback <<<<<<<<<<<", err_msg			




if __name__ == '__main__':
	s_obj = AutoSecurity()
	parser = OptionParser()
	parser.add_option( "-s", "--scan_types", dest="scan_type", action="store", help="Input single or multiple scan types seperated by comma" )
	parser.add_option( "-d", "--update_db", dest="update_db", action="store_true", help="Pass this field if you want to update QA Dashboard db" )
	( options, args ) = parser.parse_args()
	scan_types = options.scan_type.split(',')
	if options.update_db:
		update_db = True
	else:
		update_db = False
	
	for each_scan_type in scan_types:
		scan_name = s_obj.config_data[ 'nessus' ][ 'scans' ][ each_scan_type ]
		s_obj.run_security_tests( each_scan_type, scan_name, update_db )