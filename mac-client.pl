#!/usr/bin/perl

# This will handle network initialization for Mac OS X clients of GSSVPN.
# The parameters in argv will be the name of the tap device being used
# and the parameters passed back from the GSSVPN server. It will accept
# the following options
#
# ip <ip address>
# subnet <subnet mask>
# dhcp
# gateway <ip address>
# routenet <subnet address>/<cidr range>
# route <ip address>
#
# This script assumes it is running as the super-user
#

my $ipaddr = my $subnet = my $gateway = my $dhcp = undef;
my $tapdev = shift @ARGV;
my @routenets = my @routehosts = ( );

while (@ARGV) {
	$_ = shift;
	if($_ =~ /ip/) {
		$ipaddr = shift;
	}
	elsif($_ =~ /subnet/) {
		$subnet = shift;
	}
	elsif($_ =~ /gateway/) {
		$gateway = shift;
	}
	elsif($_ =~ /dhcp/) {
		system "ipconfig set $tapdev DHCP";
		$dhcp = 1;
	}
	elsif($_ =~ /routenet/) {
		push @routenets, shift;
	}
	elsif($_ =~ /route/) {
		push @routehosts, shift;
	}
}

if(!$dhcp) {
	if(!$ipaddr || !$subnet) {
		exit 1;
	}
	system "ipconfig set $tapdev MANUAL $ipaddr $subnet";
}

system "ipconfig waitall";

if(!$gateway) {
	exit 0;
}

foreach my $dest (@routenets) {
	system "route add -net $dest $gateway";
}

foreach my $dest (@routehosts) {
	system "route add -host $dest $gateway";
}
