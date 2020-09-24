#!/usr/bin/python


#usage: python list_defects.py -c <URL> -p <port> -u <username> -a <password> -s <stream>
import logging 
import csv
import json

import sys
reload(sys)
sys.setdefaultencoding('gbk')

from suds.client import *
from suds.wsse import *
from datetime import timedelta
from optparse import OptionParser

##########
# Basic operational SUDs stuff
##########
class Services :
	def __init__(self) :
		self.host = "http://127.0.0.1"
		self.port = "8080"
	
	def setHost(self, in_host) :
		self.host = in_host

	def getHost(self) :
		return self.host

	def setPort(self, in_port) :
		self.port = in_port
	
	def getPort(self) :
		return self.port

	def getURL(self, in_url) :
		return self.host + ":" + self.port + "/ws/v9/" + in_url + "?wsdl"

	def setServicesSecurity(self, client, in_user, in_pass) :
		security = Security()
		token = UsernameToken(in_user, in_pass)
		security.tokens.append(token)
		client.set_options(wsse=security)
		
##########
# 2020 09 20
# Leo Wang
# CWE and OWasP
##########
CWE = {}
#OWASP=['A1','A1','A1','A1','A1','A1','A1','A1']
#dict(zip(CWE,OWASP))

##########
# Configuration Service (WebServices)
##########
class ConfigurationService(Services) :
	def __init__(self, in_host, in_port) :
		#print "Starting ConfigurationService\n"
		self.setHost(in_host)
		self.setPort(in_port)
		self.client = Client(self.getURL("configurationservice"))
	
	def setSecurity(self, in_user, in_pass) :
		self.setServicesSecurity(self.client, in_user, in_pass)

	def create(self, in_obj) :
		return self.client.factory.create(in_obj)

	def getSnapshotsForStream(self, stream_name) :
		sido = self.client.factory.create("streamIdDataObj")
		sido.name = stream_name
		snapshots = self.client.service.getSnapshotsForStream(sido)
		return snapshots

	def getSnapshotInformation(self, snapshots) :
		snapshot_info = self.client.service.getSnapshotInformation(snapshots)
		return snapshot_info

	def getComponent(self, component_name) :
		# create a component identifier
		ciddo = self.client.factory.create("componentIdDataObj")
		ciddo.name = component_name
		return self.client.service.getComponent(ciddo)
	
	def gettriageStoreId(self, target_stream) :

		filterSpec = self.client.factory.create("streamFilterSpecDataObj")
		filterSpec.namePattern  = target_stream
		streamDataObj = self.client.service.getStreams(filterSpec)
		for stream in streamDataObj :
			return stream.triageStoreId     

	def doNotify(self, subscribers) :
		subject = "Notification of Receipt of Defects"
		message  = "<p>Your junk is broken</p><p>It is still broken</p>"
		message += "<a href=\"http://www.wunderground.com\">Wunderground</a>"
		self.client.service.notify(subscribers, subject, message)
		
	

##########
# Defect Service (WebServices)
##########
class DefectService(Services) :
	def __init__(self, in_host, in_port) :
		#print "Starting DefectService\n"
		self.setHost(in_host)
		self.setPort(in_port)
		self.client = Client(self.getURL("defectservice"))
	
	def setSecurity(self, in_user, in_pass) :
		self.setServicesSecurity(self.client, in_user, in_pass)

	def create(self, in_obj) :
		return self.client.factory.create(in_obj)

	# This method obtains CIDs that exist in a stream
	# with a given set of one or more "Classification(s)"
	# AND found by a given set of one or more "Checker(s)" 
	

	def getMergedDefectsForStreams(self, stream_name, pageSpec) :
		# create a stream identifier
		sido = self.client.factory.create("streamIdDataObj")
		sido.name = stream_name

		# create a filter to access the data we need for each of the CIDs
		filterSpec = self.client.factory.create("mergedDefectFilterSpecDataObj")
		
		snapshotScope = self.client.factory.create("snapshotScopeSpecDataObj")
		snapshotScope.showSelector = 'last()'
		
		return_cids = self.client.service.getMergedDefectsForStreams(sido, filterSpec, pageSpec, snapshotScope)
			
		return return_cids

	def getStreamDefectList(self, cid, stream_name) :
		# create a stream identifier
		sdfsdo = self.client.factory.create("streamDefectFilterSpecDataObj")
		sdfsdo.includeDefectInstances = True
		sdfsdo.includeHistory = False

		sido = self.client.factory.create("streamIdDataObj")
		sido.name = stream_name
		sdfsdo.streamIdList.append(sido)
		
		mergedDefectIdDataObj = self.client.factory.create("mergedDefectIdDataObj")
		mergedDefectIdDataObj.cid = cid.cid
		mergedDefectIdDataObj.mergeKey = cid.mergeKey
		#cids = []
		#cids.append(cid.cid)
		return self.client.service.getStreamDefects(mergedDefectIdDataObj, sdfsdo)

	def updateDefect(self, defectID, updateProperties) :
		# create a stream identifier
		return self.client.service.updateStreamDefects(defectID, updateProperties)

	def newDefectStateSpecDataObj(self) :
		return self.client.factory.create("defectStateSpecDataObj")
	
	def getTriage(self, cid, mergeKey, triageStoreId) :
		mergedDefectIdData = self.client.factory.create("mergedDefectIdDataObj")
		mergedDefectIdData.cid = cid
		mergedDefectIdData.mergeKey = mergeKey
		return self.client.service.getTriageHistory(mergedDefectIdData, triageStoreId)


##########
# Main Entry Point
##########
def main() :
	# Configuration Information
	target_stream = options.stream
	port = options.port
	hostname = options.hostname
	username = options.username
	password = options.password 
	
	
	# Begin by getting the configuration service 
	cs = ConfigurationService("http://" + hostname, port)
	cs.setSecurity(username, password)

	# get the snapshots in this stream
	ssfs = cs.getSnapshotsForStream(target_stream)

	# if we do not have any snapshots, simply return with a -1
	ln = len(ssfs);
	if ln < 1 :
		return -1

	# Begin defect service
	ds = DefectService("http://" + hostname, port)
	ds.setSecurity(username, password)

	# get CIDs from all snapshots in this stream
	#cids = ds.getSnapshotCIDs(target_stream)

	# get merged defects for the gathered CIDs 
	
	#triageStoreId  = cs.gettriageStoreId(target_stream)


	with open("Cwe_Owasp_Map.json",'r') as load_f:
		CWE = json.load(load_f)
	
	with open("result_test.csv","wb") as csvfile: 
		writer = csv.writer(csvfile)
		row = (["CID", "Checker", "Category", "Type", "Impact", "Severity", "CVSS score","Vulnerable line number","Defect remediation guidance", "CWE","OWASP"])
		writer.writerow(row)
	
		pageSpec = ds.client.factory.create("pageSpecDataObj")
		pageSpec = ds.client.factory.create("pageSpecDataObj")
		pageSpec.pageSize = 1000
		pageSpec.sortAscending = True
		pageSpec.startIndex = 0
	
		while True :
				
			cid_list = ds.getMergedDefectsForStreams(target_stream, pageSpec)

			Severity_value = ""
			CVSS_Score_value = ""
			Line_number = ""
			Remediation = ""
			cwe_value = ""
			OWasP_value = ""
			for cid in cid_list.mergedDefects :
				row = []
				row.append(cid.cid)
				row.append(cid.checkerName)
				row.append(cid.displayCategory)
				row.append(cid.displayType)
				row.append(cid.displayImpact)
				for defectStateAttribute in cid.defectStateAttributeValues:
					if defectStateAttribute.attributeDefinitionId.name == 'Severity':
						print str(defectStateAttribute.attributeDefinitionId.name)+": "+str(defectStateAttribute.attributeValueId.name)
						Severity_value = str(defectStateAttribute.attributeValueId.name)
					elif defectStateAttribute.attributeDefinitionId.name == 'CVSS_Score':
						print str(defectStateAttribute.attributeDefinitionId.name)+": "+str(defectStateAttribute.attributeValueId.name)
						CVSS_Score_value = str(defectStateAttribute.attributeValueId.name)
					else:
						if defectStateAttribute.attributeValueId :
							print str(defectStateAttribute.attributeDefinitionId.name)+": "+str(defectStateAttribute.attributeValueId.name)
						else:
							print str(defectStateAttribute.attributeDefinitionId.name)+": Don't have the attributeValueID"
				row.append(Severity_value)
				row.append(CVSS_Score_value)
				
				
				defects = ds.getStreamDefectList(cid, target_stream)
				for defect in defects :
					#print defect
					for defectInstance in defect.defectInstances :
						for event in defectInstance.events :
							if (event.main) :
								Line_number = str(event.lineNumber)
							if event.eventKind == 'REMEDIATION':
								Remediation = str(event.eventDescription)
				row.append(Line_number)
				row.append(Remediation)
				if hasattr(cid, "cwe") :
					cwe_value = str(cid.cwe)
					if cwe_value in CWE:
						OWasP_value = CWE[cwe_value]
				row.append(cwe_value)
				row.append(OWasP_value)
				print " "
				writer.writerow(row)
			pageSpec.startIndex = pageSpec.startIndex + 1000
			if len(cid_list.mergedDefectIds) < 1000 :
				break


##########
# Should be at bottom of "Main Entry Point".  Points the script back up into
# the appropriate entry function
##########
parser = OptionParser()
parser.add_option("-c", "--host", dest="hostname", 
				  help="Set hostname or IP address of CIM",
				  default="192.168.1.108")
parser.add_option("-p", "--port", dest="port",
				  help="Set port number to use",
				  default="8080")
parser.add_option("-u", "--username", dest="username",
				  help="Set username for access",
				  default="admin")
parser.add_option("-a", "--password", dest="password",
				  help="Set password for access",
				  default="fish123")
parser.add_option("-s", "--stream", dest="stream",
				  help="Set target stream for access",
				  default="InsecureCode")
>>>>>>> ba5021e2b791c0dcced618a62f81250620dad627
(options, args) = parser.parse_args()
if __name__ == "__main__" :
	main()

