use Test::More tests => 6;
use Mojo::IOLoop;

BEGIN { use_ok('MojoX::DNS') };

my $queries = 2;
my $dns = new_ok 'MojoX::DNS';
$dns->resolve('google.com', \&cb)
    ->resolve( 'ipv6tools.org', 'AAAA', \&cb);

Mojo::IOLoop->singleton->start;

sub cb {
    my $result = shift;
    ok $result, "Got resolved IPs: " . join(', ', @$result);
    is $dns->error, undef, "Error message is clean";
    Mojo::IOLoop->singleton->stop unless --$queries;
}
