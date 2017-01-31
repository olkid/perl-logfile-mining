#!/usr/bin/perl -w

use strict;
use warnings;

use Geo::IP;
use Net::SMTP;
use POSIX qw(strftime);


# process all server logwatch files
# interested in ssh failures
# combine entries
# email report


my $mbox = '/var/spool/mail/reports';
open(FH, '<:encoding(UTF-8)', $mbox) or die "Cannot open file: $mbox $!";

my $emails = 0;
my @entries;

# control variables
my $lines = 0;
my $auth = 0;
my $sshd = 0;

while (<FH>) {

  # look for section
  if ($sshd == 0) {
    # look for heading
    if ($_ =~ m/^\s*sshd\:/) {
      $sshd = 1;
      next;
    }
  }

  # found sshd; next line should be Auth Fails
  if ($sshd && !$auth) {
    if ($_ =~ m/Authentication\sFailures\:/) {
      $emails++;
      $auth = 1;
      next;
    } else {
      # wrong section, reset
      $sshd = 0;
      next;
    }
  }

  # grab 5 entries
  if ($sshd && $auth) {
    # case: does not have 5 valid entries
    if ($_ !~ m/Time/) {
      $sshd = 0;
      $auth = 0;
      $lines = 0;
      next;
    }

    # we have 5 entries
    if ($lines > 4) {
      $sshd = 0;
      $auth = 0;
      $lines = 0;
      next;
    }

    # add entry
    push @entries, $_;
    $lines++;
  }
}
close(FH);


# report variables;
my $total = 0;
my %foo = ();


my ($name, $ip, $count);

# process entries
for (@entries) {

  # format
  ($name, $ip, $count) = ($_ =~ m/\s*(.*)\s+\(([\d\.]+)\)\:\s+(\d+).*/);

  if ($name && $ip && $count) {
    # valid ipv4 addresses
  } else {
    # dns, not ip format
    ($name, $ip, $count) = ($_ =~ m/\s*(.*)\s+\((.+)\)\:\s+(\d+).*/);
  }

  # cumulative total
  $total += $count;

  if (exists $foo{$ip}) {
    # combine records
    $foo{$ip}->{count} += $count;
  } else {
    # add to hash
    my $len = 60 - length($ip);
    my $space = " " x $len;
    $foo{$ip} = {name => $name, count => $count, ip => $ip.$space};
  }
}


my $msg = '';

# open variable as a filehandle
open MSG, '>', \$msg or die $!;

print MSG "\nReport for traffic on ", strftime "%b %e, %Y", localtime(time() - 24*60*60);
print MSG "\n\nFile: ", $mbox;
print MSG "\nTotal number of emails: ", $emails;
print MSG "\n\n\nTotal authentication attempts: ", $total;
print MSG "\n\nSSHD Authentication Failures:";
print MSG "\n";

# Geo location
my $g = Geo::IP->open('GeoIP.dat', GEOIP_STANDARD) or die "$!";

# sort hash
for (sort {$foo{$b}->{count} <=> $foo{$a}->{count}} keys %foo) {
  # country name
  my $country = $g->country_name_by_addr($_);
     $country = '' if (!$country);

  print MSG "\n", $foo{$_}->{ip}, $foo{$_}->{count}, " Time(s)", "\t\t", $country;
}

print MSG "\n\n";

close MSG;


# email report
my $smtp = Net::SMTP->new('mail.example.com');

$smtp->mail('mail@example.com');
$smtp->recipient('recipient@example.com');

$smtp->data();
$smtp->datasend("From: reports\@example.com\n");
$smtp->datasend("To: recipient\@example.com\n");
$smtp->datasend("Subject: Report: SSHD Authentication Failures\n");
$smtp->datasend("\n");
$smtp->datasend("$msg");
$smtp->dataend();

$smtp->quit;


# clear mailbox
unlink $mbox;
