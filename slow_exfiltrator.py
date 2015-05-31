import re
import os
import subprocess
import base64
import hashlib
import os.path
import time
import sys

output = ""
#previous_response = subprocess.check_output("snmpgetnext -v 3 -u covert -l authPriv -a SHA -A covertpw -x AES -X covertenc -M+. 145.100.108.245:161 1.3.6.1.3.100", shell=True) #Initial message for tree entry
previous_oid = "1.3.6.1.3.100"

while 1:
 	time.sleep(float(sys.argv[1]))
	cmd = ["snmpgetnext", "-v", "3", "-u", "covert", "-l", "authPriv", "-a", "SHA", "-A", "covertpw", "-x", "AES", "-X", "covertenc", "-M+.", "145.100.108.245:161", "%s" %previous_oid]
	received_line = subprocess.check_output(cmd)
	if re.search('No more variables left in this MIB View', received_line):
		#print "Enf of MIB\n"
                break

	received_line_list = received_line.split(".")
	chunk_length = received_line_list[11]
	try:
		counter_parser_list =  received_line.split("Counter64: ")
		counter = counter_parser_list[1].strip()
	except:
		string_parser_list = received_line.split("STRING: ")
		counter = string_parser_list[1].strip()
		
	end_point = int(chunk_length) + 11
	chunk_list = []
	for j in received_line_list[12:end_point]:
		chunk_list.append(j)

	chunk_list_ascii = []
	for i in chunk_list:
		i = int(i)
		chunk_list_ascii.append(chr(i))
			
	
	chunk = "".join(chunk_list_ascii) 
	chunk = chunk[6:]	
	chunk = "\"" + chunk + "." + "\"" +  "= Counter64: " + counter
	
	if re.search('1.2.2.1.2', received_line): #GlobalFirstEntry
                line = 'GlobalFirstEntry' + chunk
	if re.search('1.3.3.1.2', received_line): #ClientFirstEntry
                line = 'ClientFirstEntry' + chunk
	
	previous_oid_list = received_line.split("=")
	previous_oid = previous_oid_list[0]
	previous_oid = previous_oid.strip()   

	output = output + line + "\n"

header_lines = []
data_lines = []
#with open('tarcan_test.txt', 'rb') as f:
#print output
for line in output.split(os.linesep):
	if re.search('ClientFirstEntry', line):
		header_lines.append(line)

filename_list = header_lines[0].split("\"")
filename = filename_list[3]

if os.path.isfile(filename) == 1:
	os.remove(filename)
	print "File exists, deleted"

checksum_list = header_lines[1].split("\"")
checksum = checksum_list[3]
print "Received checksum: " + checksum

for line in output.split(os.linesep):
        if re.search('GlobalFirstEntry', line):
                data_lines.append(line)


order_list = []
pdu_dict = {}

for i in data_lines:
	try:
		seq_list = i.split("Counter64:")
		seq = seq_list[1]
		seq = seq.strip()
		seq = int(seq)
	except:
		seq_list = i.split("INTEGER:")
		seq = seq_list[1]
                seq = seq.strip()
                seq = int(seq)
	#print "The problematic line: \n " + i
 	
	chunk_list = i.split("\"")
	chunk = chunk_list[1]
	chunk = chunk[:-1]
	chunk = chunk.strip()
	#print chunk

	pdu_dict[seq] = chunk

#print pdu_dict['2445']
#sorted_list = sorted(pdu_dict.values())	

#print sorted_list

data = ""

for key in sorted(pdu_dict.iterkeys()):
	data = data + pdu_dict[key]

data = data + "="


decoded_data = base64.b64decode(data)

with open(filename, 'wb') as g:
	g.write(decoded_data)
	g.close()

#Calculate SHA1 hash of file
BLOCKSIZE = 65536
myhash = hashlib.sha1()
with open(filename, 'rb') as afile:
	buf = afile.read(BLOCKSIZE)
        while len(buf) > 0:
		myhash.update(buf)
                buf = afile.read(BLOCKSIZE)
                sha1=myhash.hexdigest()

print "Calculat checksum: " + sha1

if sha1 == checksum:
	print filename + " is downloaded succesfully!" 
