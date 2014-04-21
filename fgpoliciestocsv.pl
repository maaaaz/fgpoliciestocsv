#!/usr/bin/perl
# This script has been originally developed by Sebastian Knoop-Troullier aka 'firewallguru' and published on http://firewallguru.blogspot.fr/2014/04/exporting-firewall-rules-to-csv.html
# Kudos to firewallguru !
 
my $output = "policies-out.csv";
 
my $policyid = 0;
my $setting = "";
my %policies;
my %seen;
my $in_policy_block = 0;
my @order_keys;
my $order_key = 0;
 
open(OUTFILE,">$output") || die "Can't open file $output: $!\n";
 
while (<>) {
    if ($in_policy_block) {
        if (/^\s*edit\s+(\d+)/i) {
            # start of new policy
            $policyid = $1;
        } elsif (/^\s*set\s+(\S+)\s+(.*)$/i) {
            # it's a setting
            my ($key,$value) = ($1,$2);
            $value =~ tr/\"\015\012\n\r//d;
            $order_keys[$order_key++] = $key unless $seen{$key}++;
            $policies{$policyid}{$key} = $value;
        } elsif (/^\s*end/i) {
            $in_policy_block = 0;
        }
    } elsif (/^\s*config firewall policy/i) {
        $in_policy_block = 1;
    }
}
 
# print out our header
print OUTFILE "id";
foreach my $key (@order_keys) {
    print OUTFILE ";$key";
}
print OUTFILE "\n";
 
# now print out each record
foreach my $policy (sort keys %policies) {
    print OUTFILE "$policy";
    foreach my $key (@order_keys) {
        if (defined($policies{$policy}{$key})) {
            print OUTFILE ";$policies{$policy}{$key}";
        } else {
            print OUTFILE ";";
        }
    }
    print OUTFILE "\n";
}
 
 
close(OUTFILE);