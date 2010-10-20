package MojoX::DNS;

use strict;
use warnings;

use base 'Mojo::Base';
our $VERSION = '0.01';

use IO::Socket;
use Mojo::IOLoop;

__PACKAGE__->attr('ioloop'  => sub{ Mojo::IOLoop->singleton });
__PACKAGE__->attr('dns'     => \&_find_dns );
__PACKAGE__->attr('dns_port'=> 53 );

sub resolve {
    my ($self, $name, $cb) = @_;

    # TODO: spice must flow
    my $transaction_id = int(rand(0x10000));
    my $flags          = 0x0100; # Standard query with recursion
    my $question       = 1;
    my $answer_rr      = 0;
    my $authority_rr   = 0;
    my $additional_rr  = 0;

    # Query in $name

    my $type           = 0x0001; # A
    my $class          = 0x0001; # IN

    # Build packet header (just for 1 query)
    my $packet         = pack( 'nnnnnn',
        $transaction_id, $flags, $question,
        $answer_rr, $authority_rr, $additional_rr,
    );

    my $query;
    foreach my $part (split /\./, $name) {
        $query .= pack('C/a', $part) if $part;
    }

    $query .= pack('Cnn', 0, $type, $class);

    $packet .= $query;

    my $socket = $self->ioloop->connect(
        address  => $self->dns,
        port     => $self->dns_port,
        args     => {
            Proto    => 'udp',
            Type     => IO::Socket::SOCK_DGRAM,
        },
        on_connect => sub {
            my ($loop, $id) = @_;
            $loop->write($id, $packet);
        },
        on_hup => sub {
            cb->(undef);
        },
        on_error => sub {
            my ($loop, $id, $error) = @_;
            warn $error;
            $cb->(undef);
        },
        on_read  => sub {
            my ($loop, $id, $chunk) = @_;
            $loop->drop( $id );

            my @ips = $self->_parse_reply( $chunk );
            $cb->(\@ips);
        }
);

}

sub _parse_reply {
    my ($self, $reply_packet) = @_;

    my @answers;
    my ($transaction, $flags, $questions,
        $answer_rr, $authority_rr,
        $additional_rr, $rest)
        = unpack ('nnnnnnA*', $reply_packet);
    # Drop queries
    # print $rest;
    for (1..$questions) {
        my ($str, $type, $class);
        # Parse hostname
        do {
            ($str, $rest) = unpack('C/aA*', $rest);
        } while ( $str );
        ($type, $class, $rest) = unpack('nnA*', $rest);
    }
    for (1..$answer_rr) {
        my ($offset, $type, $class, $ttl, $addr, $r) =
            unpack('nnnNn/AA*', $rest);
            #push @answers, $addr;
        # Unpack addr
        my @ip = unpack('C' . length($addr), $addr);
        push @answers, join('.', @ip);
        $rest = $r;
    }

    return @answers;
}

sub _find_dns {
    # TODO: parse resolve.conf
    return '8.8.8.8';
}


1;
__END__

=head1 NAME

MojoX::DNS - Asynchronous DNS resolver for Mojo

=head1 SYNOPSIS

  use MojoX::DNS;
  blah blah blah

=head1 DESCRIPTION

Stub documentation for MojoX::DNS, created by h2xs. It looks like the
author of the extension was negligent enough to leave the stub
unedited.

Blah blah blah.


=head1 SEE ALSO

Mention other useful documentation such as the documentation of
related modules or operating system documentation (such as man pages
in UNIX), or any relevant external documentation such as RFCs or
standards.

If you have a mailing list set up for your module, mention it here.

If you have a web site set up for your module, mention it here.

=head1 AUTHOR

Sergey Zasenko, E<lt>d3fin3@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2010, Sergey Zasenko

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.10.1 or,
at your option, any later version of Perl 5 you may have available.


=cut
