import sys
import yaml
import json
import smtplib
import traceback
import os
from os.path import basename
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import COMMASPACE, formatdate



class Utility:

	def __init__( self ):
		pass



	def yaml_read( self, input_file ):
		with open( input_file, 'r' ) as file_read:
			doc = yaml.load( file_read )
		return doc



	def json_read( self, json_file ):
		with open( json_file ) as data_file:
			data = json.load( data_file )
		return data

	

	def send_email( self ):
		try:
			sender = os.get_env('SENDER_EMAIL')
			receiver = os.get_env('RECEIVER_EMAIL')
			subject = "Test Subject"
			text = "Test Email Body"
			message = """\From: %s\nTo: %s\nSubject: %s\n\n%s""" % (sender, ", ".join(receiver), subject, text )
			
			smtp_obj = smtplib.SMTP('smtp.gmail.com', 587)
			smtp_obj.ehlo()
			smtp_obj.starttls()
		except:
			print >> sys.stderr, ">>>>>>>>>>>>> Sending Email Failed <<<<<<<<<<<<<<<", traceback.format_exc()


	def test( self ):
		server = smtplib.SMTP('smtp.gmail.com', 587)

		#Next, log in to the server
		server.ehlo()
		server.starttls()

		#Send the mail
		msg = "\nHello!" # The /n separates the message from the headers
		server.sendmail("badamsanthosh@gmail.com", "badamsanthosh@gmail.com", msg)

if __name__ == '__main__':
	u_obj = Utility()
	u_obj.test()