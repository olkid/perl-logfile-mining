#!/usr/bin/perl -w

use strict;
use warnings;

use DB_File;
use Fcntl;
use Geo::IP;
use MIME::Base64 qw(encode_base64);
use Net::SMTP;
use POSIX qw(strftime);
use Storable qw(freeze thaw);
use Text::CSV_XS;



# build port assignment/service name hash
my %tcp_ports;
my %udp_ports;
my $iana_file = '/etc/cron.mining/org.iana/service-names-port-numbers.csv';
{
  my $iana = Text::CSV_XS->new({binary => 1, eol => $/}) or die "Cannot use CSV_XS: ".Text::CSV_XS->error_diag();
  $iana->bind_columns(\my $service, \my $port, \my $proto, \my $descr, \my $a, \my $b, \my $c, \my $d, \my $e, \my $f, \my $g, \my $h);

  open my $assignment, '<:encoding(UTF-8)', $iana_file or die $!;

  # process each line; store value in hash
  while ($iana->getline($assignment)) {
    # skip entries with empty port values
    next unless $port;

    # some entries are ranges
    if ($port =~ m/\d+-\d+/) {

      my ($begin, $end) = ($port =~ m/(\d+)-(\d+)/);

      for ($begin..$end) {

        # add each port number in range
        $port = $_;

        # build hash
        if ($proto eq 'tcp') {
          unless ($tcp_ports{$port}) {
            $tcp_ports{$port} = $service ? $service : $descr;
          }
        } else {
          unless ($udp_ports{$port}) {
            $udp_ports{$port} = $service ? $service : $descr;
          }
        }

      }
    } else {

      # add single port number; no range

      # build hash
      if ($proto eq 'tcp') {
        unless ($tcp_ports{$port}) {
          $tcp_ports{$port} = $service ? $service : $descr;
        }
      } else {
        unless ($udp_ports{$port}) {
          $udp_ports{$port} = $service ? $service : $descr;
        }
      }

    }

  }
  close $assignment;
}


# zero padded ipv4 octets minus the dots
my %target_type = (
'000000000050' => 'firewall',
'000000000051' => 'firewall',
'000000000052' => 'firewall',

'000000000129' => 'firewall',
'000000000131' => 'firewall',
'000000000132' => 'firewall',
'000000000133' => 'load balancer',
'000000000134' => 'load balancer',
'000000000138' => 'mail server',
'000000000168' => 'media server',
'000000000169' => 'media server',
'000000000197' => 'switch',
'000000000198' => 'switch',

'000000000129' => 'firewall',
'000000000131' => 'firewall',
'000000000132' => 'firewall',
'000000000133' => 'load balancer',
'000000000134' => 'load balancer',
'000000000138' => 'mail server',
'000000000168' => 'media server',
'000000000169' => 'media server',
'000000000197' => 'switch',
'000000000198' => 'switch'
);

sub get_target_type($) {
  my $ip_key = shift;
  my $type = '';
  my $first_oct = substr($ip_key, 0, 3);
  my $last_oct = substr($ip_key, -3);

  if ($last_oct == 255) {
    $type = 'network broadcast';
  } elsif ($first_oct == '066') {
    $type = 'switch';
  } elsif ($last_oct >= 248) {
    $type = 'switch';
  } elsif ($last_oct >= 190) {
    $type = 'remote ipmi';
  } elsif ($last_oct >= 180) {
    $type = 'storage server';
  } elsif ($last_oct >= 176) {
    $type = 'power monitor';
  } elsif ($last_oct >= 170) {
    $type = 'application server';
  } elsif ($last_oct >= 160) {
    $type = 'database server';
  } elsif ($last_oct >= 150) {
    $type = 'load balancer';
  } elsif ($last_oct >= 140) {
    $type = 'application server';
  } else {
    # default
    $type = 'application server';
  }

  # override
  my $device = $target_type{$ip_key};
  $type = $device ? $device : $type;

  return $type;
}




# process log(s)
# order by port, ip
# remove duplicates
# email report

# using perl getservbyport
# lookup performed against /etc/services

sleep(3); # have seen(multiple times) the cron job run before midnight


# filenames
my $db_file     = '/etc/cron.mining/mining.db';

# since	we are not interested in time component, using 12 hours	to get yesterdays date
# I know that I	am running cron	at midnight and	I can avoid the DST edge case
my $base_file = 'intel-'.(strftime "%m-%d-%Y", localtime(time() - 12*60*60));
my $zip_file = $base_file.'.zip';
my $report_file = $base_file.'.csv';
my $report_path = '/etc/cron.mining/report/';


# file cleanup
unlink $db_file;
qx|/usr/bin/find $report_path -type f -print0 \| xargs -0 /bin/rm -f|;


# open Berkeley DB
# enable duplicate keys
#$DB_BTREE->{'flags'} = R_DUP;
  # edit: no duplicates allowed (default)
my $x = tie my %btree, 'DB_File', $db_file, O_CREAT|O_RDWR, 0644, $DB_BTREE || die "Cannot create mining.db: $!\n";


my @logs = ();
# todo: dynamic log lookup
push @logs, '/var/log/firewall.1';
push @logs, '/data/log/firewall-all-traffic.1';


my %ports;

# parse the log files and store relevant data in sorted btree
for my $log(@logs) {

  open FH, '<:encoding(UTF-8)', $log or die "Cannot open file: $log $!";

  while (<FH>) {

    # parse log entries
      # Aug 10 15:33:53 kernel: Dropped IN=eth1 OUT=eth0 SRC= DST= LEN=40 TOS=0x08 PREC=0x40 TTL=46 ID=2893 PROTO=TCP SPT=3685 DPT=23 WINDOW=1320 RES=0x00 SYN URGP=0
    my ($date, $src, $dst, $proto, $dpt) = ($_ =~ m/^(\w+\s+\d+\s+[\d:]+).*SRC=([^\s]*)\sDST=([^\s]*)\sLEN.*PROTO=([^\s]*)\sSPT.*DPT=(\d+)\s/);

    # case: unexpectedly missing fields, fill in what we can
    unless ($date) {
      ($date) = ($_ =~ m/^(\w+\s+\d+\s+[\d:]+)/);
       $date ||= '';
    }
    unless ($src) {
      ($src) = ($_ =~ m/SRC=([^\s]*)\s/);
       $src ||= '';
    }
    unless ($dst) {
      ($dst) = ($_ =~ m/DST=([^\s]*)\s/);
       $dst ||= '';
    }
    unless ($proto) {
      ($proto) = ($_ =~ m/PROTO=([^\s]*)\s/);
       $proto ||= '';
    }
    unless (defined $dpt) {
      ($dpt) = ($_ =~ m/DPT=(\d+)\s/);
       $dpt ||= '';
    }

    # normalize to lower case
    $proto = lc $proto;

    # normalize ipv4 address into sortable representation
    my $i_src = sprintf('%03.f%03.f%03.f%03.f', split /\./, $src);
    my $i_dst = sprintf('%03.f%03.f%03.f%03.f', split /\./, $dst);

    # duplicate key allowed
#    my $j = $i_src.$dpt.$i_dst;
      # remove duplicates; distinct across columns
      my $oct_dst = substr($i_dst, -3);
      my $j = $i_src.$proto.$dpt.$oct_dst;

    # serialize data and insert into db
    $btree{$j} = freeze({date => $date, src => $src, dst => $dst, proto => $proto, dpt => $dpt, dst_key => $i_dst});

    # add port to list
    $ports{$dpt} = 1;
  }

  close(FH);
}



# write report
my $csv = Text::CSV_XS->new({binary => 1, eol => $/}) or die "Cannot use CSV_XS: ".Text::CSV_XS->error_diag();
open my $fh, '>:encoding(UTF-8)', $report_path.$report_file or die $!;

# column headers
my @h = ['Date', 'Port', 'Source IP', 'Protocol', 'Type', 'Country', 'Target', 'Destination IP'];
$csv->print($fh, @h);

# Geo location
my $g = Geo::IP->open('/etc/cron.mining/geoip/GeoIP.dat', GEOIP_STANDARD) or die "$!";


# loop through ports in sorted order
for my $port(sort {$a <=> $b} keys %ports) {

  # read records out in sorted order by ip address
    # contains duplicate keys
  my ($key, $value) = (0, 0);
  for (my $sth = $x->seq($key, $value, R_FIRST);
          $sth == 0;
          $sth = $x->seq($key, $value, R_NEXT)) {

    # unserialize
    my $record = thaw($value);

    # process record if it matches port
    if ($record->{dpt} == $port) {

      # country name
      $record->{country} = $g->country_name_by_addr($record->{src});
      $record->{country} = '' unless $record->{country};

      # service name
      my $service = getservbyport($record->{dpt}, $record->{proto});
      unless ($service) {
        if ($record->{proto} eq 'tcp') {
          $service = $tcp_ports{$record->{dpt}};
        } else {
          $service = $udp_ports{$record->{dpt}};
        }
      }
#      $record->{service} = getservbyport($record->{dpt}, $record->{proto});
      $record->{service} = $service;
      $record->{service} = '' unless $record->{service};

      # entity type
      $record->{target_type} = get_target_type($record->{dst_key});

      my $data = [$record->{date}, $record->{dpt}, $record->{src}, $record->{proto}, $record->{service}, $record->{country}, $record->{target_type}, $record->{dst}];
      $csv->print($fh, $data);

      # remove record after processing
      $x->del_dup($key, $value);
    }
  }

}


# close Berkeley DB
undef $x;
untie %btree;

# close filehandle
close $fh;


# compress the csv file
qx|/usr/bin/zip -j $report_path$zip_file $report_path$report_file|;



# email report
my $msg = "Daily Intelligence Report\n\nFile: $zip_file\nFormat: compressed CSV\nrecord separator: newline\nfield separator: comma";

my $boundary = q|qwertyuiop|;
my $smtp = Net::SMTP->new('mail.example.com');

$smtp->mail('mail@example.com');
$smtp->recipient('recipient@example.com');

$smtp->data();
$smtp->datasend("From: reports\@example.com\n");
$smtp->datasend("To: recipient\@example.com\n");
$smtp->datasend("Subject: Report: Intelligence Feed\n");
$smtp->datasend("MIME-Version: 1.0\n");
$smtp->datasend("Content-type: multipart/mixed;\n\tboundary=\"$boundary\"\n");
$smtp->datasend("\n");

$smtp->datasend("--$boundary\n");
$smtp->datasend("Content-Type: text/plain;\n");
$smtp->datasend("Content-Disposition: quoted-printable\n");
$smtp->datasend("\n$msg\n\n");
$smtp->datasend("\n");

$smtp->datasend("--$boundary\n");
$smtp->datasend("Content-Type: application/zip; name=\"$zip_file\"\n");
$smtp->datasend("Content-Transfer-Encoding: base64\n");
$smtp->datasend("Content-Disposition: attachment; filename=\"$zip_file\"\n");
$smtp->datasend("\n");

my $buf;
open FH, '<', $report_path.$zip_file or warn "Failed to open file: $report_path.$zip_file $!";
  binmode(FH);
  local $/ = undef;
  while (read (FH, my $i, 72*57)) {
    $buf = &encode_base64($i);
    $smtp->datasend($buf);
  }
close FH;

$smtp->datasend("\n");

$smtp->datasend("--$boundary--\n");
$smtp->dataend();

$smtp->quit;
