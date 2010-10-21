use Test::More tests => 6;
use Mojo::IOLoop;

BEGIN { use_ok('MojoX::DNS') };

my $dns = new_ok 'MojoX::DNS';
$dns->resolve(
    'google.com', 
    sub {
        my $result = shift;
        ok $result, "Got resolved IPs: " . join(', ', @$result);
        is $dns->error, undef, "Error message is clean";

        # IPV6 resolve
        $dns->resolve(
            'ipv6tools.org', 'AAAA', sub {
                my $result = shift;
                ok $result, "Got resolved IPs: " . join(', ', @$result);
                is $dns->error, undef, "Error message is clean";
                Mojo::IOLoop->singleton->stop;
            }
        );
});

Mojo::IOLoop->singleton->start;
