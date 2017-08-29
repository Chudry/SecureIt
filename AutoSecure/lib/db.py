import MySQLdb
import sys, os, traceback
from utility import Utility
import pdb
import datetime


class MySQLConnector:

	def __init__( self, host, user, password, database ):
		self.db = MySQLdb.connect( host, user, password, database )


	def fetch_data( self, query ):
		try:
			#pdb.set_trace()
			cursor = self.db.cursor( MySQLdb.cursors.DictCursor )
			cursor.execute( query )
			result = cursor.fetchall()
			return result
		except:
			print >> sys.stderr, "\n>>>>>>>>>>> DB Query Failed with Traceback <<<<<<<<<<<<<<<<<<<<<\n", traceback.format_exc()


	def execute_query( self, query ):
		try:
			cursor = self.db.cursor()
			cursor.execute( query )
			self.db.commit()

		except:
			self.db.rollback()
			print >> sys.stderr, "\n>>>>>>>>>>>>>>>>>>> Query execution failed with traceback <<<<<<<<<<<<<<<<<<\n", traceback.format_exc()


	def get_last_insert_id( self ):
		try:
			get_id_query = """ SELECT LAST_INSERT_ID() AS ID """
			return self.fetch_data( get_id_query )[0][ 'ID' ]
		except:
			print >> sys.stderr, ">>>>>>>>>>>>>>>>> Unable to get last insert ID <<<<<<<<<<<<<<<<<<"


	def update_secutiry_dashboard_tables( self, open_port_hosts, hosts_total_info ):
		try:
			#pdb.set_trace()
			severity_map = { '0': 'Info', '1':'Low', '2':'Medium', '3':'High', '4':'Critical' }
			scan_type = hosts_total_info[ 'scan_type' ]
			scan_name = hosts_total_info[ 'scan_name' ]
			exec_id = hosts_total_info[ 'scan_uuid' ]
			for each_host in hosts_total_info:

				if each_host in ( 'scan_uuid', 'scan_name', 'scan_type' ):
					continue

				severity_info = hosts_total_info[ each_host ][ 'severity' ]
				vul_info = hosts_total_info[ each_host ][ 'vulnerabilities' ]

				#Check if Scan with ID already exists
				time_stamp = datetime.datetime.today()
				sec_exec_insert_query = """ INSERT INTO sec_test_exec ( exec_id, host_name, scan_type, scan_name, critical, high, medium, low, info, exec_ts ) VALUES ( '%s', '%s', '%s', '%s', %d, %d, %d, %d, %d, '%s'  ) """ % ( exec_id, each_host, scan_type, scan_name, severity_info['Critical'], severity_info['High'], severity_info['Medium'], severity_info['Low'], severity_info['Info'], time_stamp )
				self.execute_query( sec_exec_insert_query )
				st_id = self.get_last_insert_id()

				for each_vul in vul_info:
					severity = severity_map[ str(each_vul['severity']) ]
					sec_vul_insert_query = """ INSERT INTO sec_vul_info ( severity, family, name, vul_index, severity_index, st_id, count, plugin_id ) VALUES ( '%s', '%s', '%s', %d, %d, %d, %d, %d ) """ % ( severity, each_vul['plugin_family'], each_vul['plugin_name'], each_vul['vuln_index'], each_vul['severity_index'], st_id, each_vul['count'], each_vul['plugin_id'] )
					self.execute_query( sec_vul_insert_query )

				host_ports = open_port_hosts[ each_host ]
				for each_port in host_ports:
					severity_info_insert_query = """ INSERT INTO sec_open_ports_services ( port_num, proto, service_name, st_id ) VALUES ( %d, '%s', '%s', %d ) """ % ( each_port, host_ports[ each_port ][ 'proto' ], host_ports[ each_port ][ 'service' ], st_id )
					self.execute_query( severity_info_insert_query )
				
		except:
			print >> sys.stderr, "\n>>>>>>>>>>>>>>>>>>>> Unable to update Security Test Results <<<<<<<<<<<<<<<<<<<<<<\n", traceback.format_exc()
			pdb.set_trace()



if __name__ == '__main__':
	db_obj = MySQLConnector()
	query = "select id, first_name, last_name, email from users"
	db_obj.do_query( query )