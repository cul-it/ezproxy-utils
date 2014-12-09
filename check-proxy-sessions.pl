#!/usr/bin/perl

use strict;
use POSIX qw(strftime);
use Socket qw(inet_ntoa);
use Getopt::Long;
use Pod::Usage;

## Configurable Options
#
# Session length: "Long" session length in seconds.  Default is 21600 seconds (six hours).
my $session_length = 21600;

# EZproxy directory: the directory that contains the ezproxy.hst file.  Default is '/ezproxy'
my $dirpath = '/ezproxy';

my $help = 0;

GetOptions(
    'length=i' => \$session_length,
    'dir=s'    => \$dirpath,
    'help'     => \$help,
) or pod2usage(2);

pod2usage(1) if $help;


## Read in the status file
open( IN, "$dirpath/ezproxy.hst" )
  or die "Could not open EZProxy status file ($dirpath/ezproxy.hst): \n$!";

## Calculate

my $now = localtime();

print "Checking EZProxy sessions longer than $session_length seconds: $now\n";

my %sessions;
my $session_id = "";

while ( my $line = <IN> ) {
    next if ( $line =~ /^[HPM]/ );
    chomp($line);

    my @parts = split( /\s/, $line );
    if ( $parts[0] eq 'S' ) {
        $session_id                         = $parts[1];
        $sessions{$session_id}{start_time}  = $parts[2];
        $sessions{$session_id}{last_access} = $parts[3];
        $sessions{$session_id}{ip_address}  = $parts[6];
    }
    elsif ( $parts[0] eq 'L' ) {
        $sessions{$session_id}{user} = $parts[1];
    }
    elsif ( $parts[0] eq 'I' ) {
        $sessions{$session_id}{sourceip} = $parts[1];
    }
    elsif ( $parts[0] eq 'g' ) {
        push @{ $sessions{$session_id}{groups} }, $parts[1];
    }

    if ( $sessions{$session_id}{start_time} =~ /\./ ) {
        my ( $a, $b ) = split( /\./, $sessions{$session_id}{start_time} );
        $sessions{$session_id}{start_time} = $a;
    }

    $sessions{$session_id}{start_time_converted} =
      strftime( "%Y-%m-%d %H:%M:%S",
        localtime( $sessions{$session_id}{start_time} ) );
    $sessions{$session_id}{last_access_converted} =
      strftime( "%Y-%m-%d %H:%M:%S",
        localtime( $sessions{$session_id}{last_access} ) );

    $sessions{$session_id}{ip_address_converted} =
      inet_ntoa( pack( "L", $sessions{$session_id}{ip_address} ) );

    $sessions{$session_id}{session_age} =
      $sessions{$session_id}{last_access} - $sessions{$session_id}{start_time};
    $sessions{$session_id}{session_age_converted} = sprintf(
        "%2.2d:%2.2d:%2.2d",
        ( $sessions{$session_id}{session_age} / ( 60 * 60 ) ),
        ( $sessions{$session_id}{session_age} / 60 ) % 60,
        $sessions{$session_id}{session_age} % 60
    );

}

foreach $session_id ( keys %sessions ) {
    if ( $sessions{$session_id}{session_age} > $session_length ) {
        print "$session_id\t$sessions{$session_id}{ip_address_converted}\t";
        print
"$sessions{$session_id}{session_age_converted}\t$sessions{$session_id}{user}\n";
    }

}

__END__

=head1 NAME

check-proxy-sessions.pl - Check EZProxy state file for long-running sessions

=head1 SYNOPSIS

check-proxy-sessions.pl [options]

 Options:
   -d, --dir=     Directory that contains the ezproxy.hst file
                  (default is /ezproxy)
   -l, --length=  Length of a session, in seconds, for it to qualify as "long"
                  (default is 21600, or six hours)
   -h, --help     brief help message

=head1 DESCRIPTION

This program will read in the contents of the EZProxy server state file (ezproxy.hst) and parse the lines
related to user sessions.  It will calculate the length of the sessions, and report out any sessions
that have been alive for more than the designated length of time (six hours by default).

This should be useful in identifying compromized credentials or abusive downloaders, as a normal EZProxy session
will timeout after a reasonable amount of inactivity.

=cut
