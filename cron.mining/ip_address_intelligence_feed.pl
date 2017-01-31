#!/usr/bin/perl -w

use strict;
use warnings;

use DB_File;
use Fcntl;
use Geo::IP;
use Net::SMTP;
use POSIX qw(strftime);
use Storable qw(freeze thaw);
use Text::CSV_XS;


# process log(s)
# report unique ip address
# email report

# filenames
my $db_file     = '/etc/cron.mining/mining_ip.db';
# since	we are not interested in time component, using 12 hours	to get yesterdays date
# I know that I	am running cron	at midnight and	I can avoid the DST edge case
my $report_file = 'intel-ip-'.(strftime "%m-%d-%Y", localtime(time() - 12*60*60)).'.csv';
my $report_path = '/etc/cron.mining/report/';


# file cleanup
unlink $db_file;
#qx|/usr/bin/find $report_path -type f -print0 \| xargs -0 /bin/rm -f|;
  # path is cleaned up by script: intelligence_feed.pl
  # this script will be set to run after intelligence feed script


# open Berkeley DB
# enable duplicate keys
#$DB_BTREE->{'flags'} = R_DUP;
  # edit: no duplicates allowed (default)
my $x = tie my %btree, 'DB_File', $db_file, O_CREAT|O_RDWR, 0644, $DB_BTREE || die "Cannot create mining_ip.db: $!\n";


my @logs = ();
# todo: dynamic log lookup
push @logs, '/var/log/firewall.1';
push @logs, '/data/log/firewall-all-traffic.1';


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

    # normalize ipv4 address into sortable representation
    my $i_src = sprintf('%03.f%03.f%03.f%03.f', split /\./, $src);

    # serialize data and insert into db
    $btree{$i_src} = freeze({src => $src});
  }

  close(FH);
}



# write report
my $csv = Text::CSV_XS->new({binary => 1, eol => $/}) or die "Cannot use CSV_XS: ".Text::CSV_XS->error_diag();
open my $fh, '>:encoding(UTF-8)', $report_path.$report_file or die $!;

# column headers
my @h = ['Source IP', 'Country'];
$csv->print($fh, @h);

# Geo location
my $g = Geo::IP->open('/etc/cron.mining/geoip/GeoIP.dat', GEOIP_STANDARD) or die "$!";


# read records out in sorted order by ip address
  # contains duplicate keys
my ($key, $value) = (0, 0);
for (my $sth = $x->seq($key, $value, R_FIRST);
        $sth == 0;
        $sth = $x->seq($key, $value, R_NEXT)) {

  # unserialize
  my $record = thaw($value);

  # country name
  $record->{country} = $g->country_name_by_addr($record->{src});
  $record->{country} = '' unless $record->{country};

  my $data = [$record->{src}, $record->{country}];
      $csv->print($fh, $data);

  # remove record after processing
  $x->del_dup($key, $value);

}


# close Berkeley DB
undef $x;
untie %btree;

# close filehandle
close $fh;



# email report
my $msg = "Daily IP Address Intelligence Report\n\nFile: $report_file\nFormat: CSV\nrecord separator: newline\nfield separator: comma";

my $boundary = q|qwertyuiop|;
my $smtp = Net::SMTP->new('mail.example.com');

$smtp->mail('mail@example.com');
$smtp->recipient('recipient@example.com');

$smtp->data();
$smtp->datasend("From: reports\@example.com\n");
$smtp->datasend("To: recipient\@example.com\n");
$smtp->datasend("Subject: Report: IP Address Intelligence Feed\n");
$smtp->datasend("MIME-Version: 1.0\n");
$smtp->datasend("Content-type: multipart/mixed;\n\tboundary=\"$boundary\"\n");
$smtp->datasend("\n");

$smtp->datasend("--$boundary\n");
$smtp->datasend("Content-Type: text/plain;\n");
$smtp->datasend("Content-Disposition: quoted-printable\n");
$smtp->datasend("\n$msg\n\n");
$smtp->datasend("\n");

$smtp->datasend("--$boundary\n");
$smtp->datasend("Content-Type: application/text; name=\"$report_file\"\n");
$smtp->datasend("Content-Disposition: attachment; filename=\"$report_file\"\n");
$smtp->datasend("\n");

my $buf;
open FH, '<:encoding(UTF-8)', $report_path.$report_file or warn "Failed to open file: $report_path.$report_file $!";
  local $/ = undef;
  while (read (FH, my $i, 72*57)) {
    $smtp->datasend($i);
  }
close FH;

$smtp->datasend("\n");

$smtp->datasend("--$boundary--\n");
$smtp->dataend();

$smtp->quit;
