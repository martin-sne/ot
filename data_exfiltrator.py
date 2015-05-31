import re
import os
import subprocess
import base64
import hashlib
import os.path

output = subprocess.check_output("snmpwalk -v 3 -u covert -l authPriv -a SHA -A covertpw -x AES -X covertenc -M+. 145.100.108.245:161 COVERT-CHANNEL-MIB::covertchannelmib", shell=True)

#print output

header_lines = []
data_lines = []
#with open('tarcan_test.txt', 'rb') as f:
#print output
for line in output.split(os.linesep):
	if re.search('ClientFirstEntry', line):
		header_lines.append(line)

filename_list = header_lines[0].split("\"")
filename = filename_list[1]

if os.path.isfile(filename) == 1:
	os.remove(filename)
	print "File exists, deleted"


checksum_list = header_lines[1].split("\"")
checksum = checksum_list[1]
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
 	
	chunk_list = i.split("\"")
	chunk = chunk_list[1]
	chunk = chunk[:-1]
	chunk = chunk[6:]
	chunk = chunk.strip()		
	#print chunk

	pdu_dict[seq] = chunk

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
