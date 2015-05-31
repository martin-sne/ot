#!/usr/bin/perl -w
# $id ml 


use MIME::Base64;
$decoded = decode_base64($encoded);

my $snmp_bin = '/usr/bin/snmpwalk';
my $version = '3';
my $user = 'covert';
my $secLevel = 'authPriv';
my $authProtocol = 'SHA';
my $authPassword = 'covertpw';
my $privProtocol = 'AES';
my $privPassword = 'covertenc';
my $miblocation = '-M+.'; 
my $host = 'localhost';
my $port = '5555';
my $info = 'COVERT-CHANNEL-MIB::covertchannelClientFirstEntry';
my $data = 'COVERT-CHANNEL-MIB::covertchannelGlobalFirstEntry';

my %dictionary = ();

my @info= `$snmp_bin -v $version -u $user -l $secLevel -a $authProtocol -A $authPassword -x $privProtocol -X $privPassword $miblocation $host:$port $info -Ovq`;

my $file = $info[0];
my $hash = $info[1];

my @data= `$snmp_bin -v $version -u $user -l $secLevel -a $authProtocol -A $authPassword -x $privProtocol -X $privPassword $miblocation $host:$port $data`;

#print $file;
#print $hash;

foreach $item (@data) {
	if ($item =~ m/^.*\"(.*)\.\".*INTEGER:(.*)$/) {
		 $dictionary{$1} = $2; 
	}
}


foreach my $chunk (sort { $dictionary{$a} <=> $dictionary{$b} } keys %dictionary) {

    	print "$chunk => $dictionary{$chunk}\n";
}



