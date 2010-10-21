package MojoX::DNS;

use strict;
use warnings;

use base 'Mojo::Base';
our $VERSION = '0.01';

use IO::Socket ();
use Mojo::IOLoop ();
use Carp ();

__PACKAGE__->attr('ioloop'  => sub{ Mojo::IOLoop->singleton });
__PACKAGE__->attr('dns'     => \&_find_dns );
__PACKAGE__->attr('dns_port'=> 53 );
__PACKAGE__->attr('error');
__PACKAGE__->attr('timeout' => 15 );

my $TYPE_A    = 0x0001;
my $TYPE_AAAA = 0x001c;

sub resolve {
    my ($self, $name, $query_type, $cb) = @_;

    if (ref $query_type eq 'CODE') {
        $cb   = $query_type;
        $query_type = 'A';
    }

    # TODO: spice must flow
    my $transaction_id = int( rand(0x10000) );
    my $flags          = 0x0100; # Standard query with recursion
    my $question       = 1;
    my $answer_rr      = 0;
    my $authority_rr   = 0;
    my $additional_rr  = 0;

    # Build packet header (just for 1 query)
    my $packet         = pack( 'nnnnnn',
        $transaction_id, $flags, $question,
        $answer_rr, $authority_rr, $additional_rr,
    );

    # Query
    my $query;
    my $type;
    my $class          = 0x0001; # IN

    if ($query_type eq 'A') {
        $type =  $TYPE_A;
    } elsif ($query_type eq 'AAAA') {
        $type =  $TYPE_AAAA;
    } else {
        Carp::croak "Unsupported query type \"$query_type\"";
    }

    foreach my $part (split /\./, $name) {
        $query .= pack('C/a', $part) if $part;
    }

    $query .= pack('Cnn', 0, $type, $class);

    $packet .= $query;

    my $session = {
        packet  => $packet,
        cb      => $cb,
        dns     => 0,
        transaction => $transaction_id,
    };

    $self->_send_request( $session );
    return $self;
}

sub _send_request {
    my ($self, $session) = @_;

    my $timeout;
    my $socket;

    $socket = $self->ioloop->connect(
        address  => $self->dns->[$session->{dns}],
        port     => $self->dns_port,
        args     => {
            Proto    => 'udp',
            Type     => IO::Socket::SOCK_DGRAM,
        },
        on_connect => sub {
            my ($loop, $id) = @_;
            $loop->write($id, $session->{packet});
        },
        on_error => sub {
            my ($loop, $id, $error) = @_;
            $self->_process_error( $session, $socket, $timeout, $error );
        },
        on_read  => sub {
            my ($loop, $id, $chunk) = @_;

            if ( my $error = $self->_process_reply( $session, $chunk ) ) {
                $self->_process_error( $session, $socket, $timeout, $error );
            } else {
                # Otherwise user got result
                $self->ioloop->drop( $socket );
                $self->ioloop->drop( $timeout );
            }
        }
    );

    $timeout = $self->ioloop->timer(
        $self->timeout => sub {
            $self->_process_error( $session, $socket, $timeout, "timeout" );
        }
    );
}

sub _process_error {
    my ($self, $session, $socket, $timeout, $error) = @_;

    $self->ioloop->drop( $socket );
    $self->ioloop->drop( $timeout );

    # Try next DNS
    unless ( $self->dns->[++$session->{dns}]) {
        $self->error( $error );
        $session->{cb}( undef );
    } else {
        $self->_send_request( $session );
    }
}

sub _process_reply {
    my ($self, $session, $reply_packet) = @_;

    my @answers;
    my ($transaction, $flags, $questions,
        $answer_rr, $authority_rr,
        $additional_rr, $rest)
        = unpack ('nnnnnnA*', $reply_packet);

    # Wrong transaction?
    unless ($session->{transaction} == $transaction) {
        return "Wrong transaction id";
    }

    unless ($flags & 0x8000) {
        return "Not a response";
    }

    if (my $reply_code = ($flags & 0xf)) {
        return sprintf "Got error reply code: %X", $reply_code;
    }

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
        if ($type == $TYPE_A) {
            my @result = unpack('C' . length($addr), $addr);
            push @answers, join('.', @result);
        } elsif ($type == $TYPE_AAAA) {
            my @result = unpack('n' . (length($addr)>>1), $addr);
            push @answers, sprintf('%x:%x:%x:%x:%x:%x:%x:%x', @result);
        }
        $rest = $r;
    }

    # Return data to callback
    $session->{cb}->( \@answers );

    return undef;
}

sub _find_dns {
    my @servers;
    open F, '/etc/resolv.conf' or Carp::croak "Can't open /etc/resolv.conf: $!";
    my @resolv = <F>;
    close F;
    chomp @resolv;
    foreach my $l (grep /^\s*nameserver/, @resolv) {
        $l=~m{nameserver\s+([^\s]+)};
        push @servers, $1;
    }
    Carp::croak "Got no DNS server" unless @servers;
    return \@servers;
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
