import sys, os
import traceback
from msfrpc import Msfrpc
import msgpack
import time
import pdb


class MetaSploitFrameWork:

	def __init__( self ):
		self.msf_client = Msfrpc( {} )



	def setup( self, user, password ):
		try:
			self.msf_client.login( user=user, password=password )
			print >> sys.stderr, ">>>>>>>>>>>>>> Successfully Logged into MetaSploit <<<<<<<<<<<<<<<<"

		except:
			err_msg = traceback.format_exc()
			print >> sys.stderr, "\n>>>>>>>>>>>>  MetaSploit SetUp Failed <<<<<<<<<<<\n", err_msg, "\n"
			sys.exit()




	def create_console( self ):
		try:
			console = self.msf_client.call( 'console.create' )
			print >> sys.stderr, "\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~ MSF Console Created ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"
			return console[ 'id' ]

		except:
			sys.exit()




	def command_execution( self, console_id, command ):
		try:
			print >> sys.stdout, ">>> Going to execute Command: %s <<<" % ( command )
			self.msf_client.call( 'console.write', [console_id, command] )
			time.sleep(1)
			exec_data = ""
			while True:
				res = self.msf_client.call('console.read',[console_id])
				if res[ 'busy' ] == True:
					if len(res['data']) > 1:
						exec_data = exec_data+res[ 'data' ]
				else:
					break
			return exec_data
		except:
			err_msg = traceback.format_exc()
			print >> sys.stderr, ">>>>>>>>> Msf Command Execution failed with traceback <<<<<<<<<<<", err_msg
			return False
		


	def report_openport_hosts( self ):
		try:
			host_services = self.msf_client.call( 'db.services', [ {} ] )['services']
			"""
			get_services should work. There seems to be a bug in Msfrpc. For now using db.services and filter 
			the open ports.
			"""
			
			open_port_hosts = {}
			for each_service in host_services:
				if each_service[ 'state' ] == 'open':
					curr_host = each_service[ 'host' ]
					if curr_host not in open_port_hosts.keys():
						open_port_hosts[ curr_host ] = {}
					
					open_port_hosts[ curr_host ][ each_service[ 'port' ] ] = {}
					open_port_hosts[ curr_host ][ each_service[ 'port' ] ]['proto'] = each_service[ 'proto' ]
					open_port_hosts[ curr_host ][ each_service[ 'port' ] ]['service'] = each_service[ 'name' ]
					
			return open_port_hosts
			

		except:
			err_msg = traceback.format_exc()
			print >> sys.stderr, ">>>>>>>>>> Reporting OpenPorHosts Failed with traceback <<<<<<<<<", err_msg



	def destroy_console( self, console_id ):
		self.msf_client.call('console.destroy',[ console_id ])
		print >> sys.stdout, "\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~ MSF Console Destroyed ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"




if __name__ == '__main__':
	pass