#!/usr/bin/perl -w

use strict;
use warnings;

use MIME::Base64 qw(encode_base64);
use GD::Graph::bars;
use Geo::IP;
use Net::SMTP;
use POSIX qw(strftime);


# process all server logwatch files
# interested in dropped ssh connections
# combine entries
# email report


my $mbox = '/var/spool/mail/reports';
open(FH, '<:encoding(UTF-8)', $mbox) or die "Cannot open file: $mbox $!";

my $emails = 0;
my @entries;

# control variables
my $firewall = 0;

while (<FH>) {

my ($ip, $num);

  # look for section
  if ($firewall == 0) {
    # look for heading
    if ($_ =~ m/iptables\sfirewall\sBegin/) {
      $firewall = 1;
      next;
    }
  }

  # found "iptables firewall"; next line should be Auth Fails
  if ($firewall) {
    if ($_ =~ m/iptables\sfirewall\sEnd/) {
      $firewall = 0;
      next;
    }

    if ($_ =~ m/From\s(.*)\s-\s(\d+)\spacket/) {
      $ip  = $1;
      $num = $2;

      # add entry
      push @entries, {ip => $ip, count => $num};
    }
  }
}
close(FH);


# report variables;
my $total = 0;
my %foo = ();

# Geo location
my $g = Geo::IP->open('GeoIP.dat', GEOIP_STANDARD) or die "$!";

# process entries
for (@entries) {

  # country name
  my $country = $g->country_name_by_addr($_->{ip});
     $country = 'UNKNOWN' if (!$country);

  # cumulative total
  $total += $_->{count};

  if (exists $foo{$country}) {
    # combine records
    $foo{$country}->{count} += $_->{count};
  } else {
    # add to hash
    my $len = 60 - length($country);
    my $space = " " x $len;
    $foo{$country} = {count => $_->{count}, space => $space};
  }
}


my $msg = '';

# open variable as a filehandle
open MSG, '>', \$msg or die $!;

print MSG "\nReport for traffic on ", strftime "%b %e, %Y", localtime(time() - 24*60*60);
print MSG "\n\n\nTotal authentication attempts: ", $total;
print MSG "\n\nDropped Packets:";
print MSG "\n";


my (@x, @y);

# sort hash
for (sort {$foo{$b}->{count} <=> $foo{$a}->{count}} keys %foo) {
  print MSG "\n", $_, $foo{$_}->{space}, "\t\t", $foo{$_}->{count};
push @x, $_;
push @y, $foo{$_}->{count};
}

# graph
my $graph = GD::Graph::bars->new(1200, 600);
my @data = (\@x, \@y);

# attribute guide
  # http://wellington.pm.org/archive/201002/grant-gd-graph/toc.html
  # https://www.safaribooksonline.com/library/view/perl-graphics-programming/9781449358280/ch04s04.html
$graph->set(
  x_label => "Country",
  y_label => "Dropped Packets",
  title => "SSHD Attempts",
  x_labels_vertical => 1,
  show_values => 1,
  dclrs => ['blue', 'green', 'yellow', 'red', 'orange'],
  transparent => 0,
  bgclr => 'white',
  boxclr => 'white',
  fgclr => '#aaaaaa',
  cycle_clrs => 1,
  bar_spacing => 3,
  x_label_position => 0.5,
  box_axis => 0,
  x_ticks => 0,
  axislabelclr => '#000000',
  labelclr => '#000000',
  textclr => '#000000',
  borderclrs => [undef],
  long_ticks => 0,
  valuesclr => '#000000'
) or warn $graph->error;

my $ff = '/usr/share/fonts/google-crosextra-caladea/Caladea-Regular.ttf';
$graph->set_title_font($ff, 20);
$graph->set_x_label_font($ff, 16);
$graph->set_y_label_font($ff, 16);
$graph->set_x_axis_font($ff, 14);
$graph->set_y_axis_font($ff, 14);

my $img = $graph->plot(\@data) or die $graph->error;
open(FH, '>/tmp/report_graph.png') or die $!;
binmode FH;
print FH $img->png;
close FH;

print MSG "\n\n";

close MSG;


# email report
my $boundary = q|qwertyuiop|;

my $smtp = Net::SMTP->new('mail.example.com');

$smtp->mail('mail@example.com');
$smtp->recipient('recipient@example.com');

$smtp->data();
$smtp->datasend("From: reports\@example.com\n");
$smtp->datasend("To: recipient\@example.com\n");
$smtp->datasend("Subject: Report: Dropped Packets By Country\n");
$smtp->datasend("MIME-Version: 1.0\n");
$smtp->datasend("Content-type: multipart/mixed;\n\tboundary=\"$boundary\"\n");
$smtp->datasend("\n");

$smtp->datasend("--$boundary\n");
$smtp->datasend("Content-Type: text/plain;\n");
$smtp->datasend("Content-Disposition: quoted-printable\n");
$smtp->datasend("$msg");
$smtp->datasend("\n");

$smtp->datasend("--$boundary\n");
$smtp->datasend("Content-Type: image/png; name=\"report_graph.png\"\n");
$smtp->datasend("Content-Transfer-Encoding: base64\n");
$smtp->datasend("Content-Disposition: attachment; filename=\"report_graph.png\"\n");
$smtp->datasend("\n");

my $buf;
open(FH, "</tmp/report_graph.png") || warn "Failed to open binary file $!";
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


# clear mailbox
#unlink $mbox;
