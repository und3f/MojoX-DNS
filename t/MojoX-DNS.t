use Test::More tests => 3;
use Mojo::IOLoop;

BEGIN { use_ok('MojoX::DNS') };

my $dns = new_ok 'MojoX::DNS';
$dns->resolve(
    'google.com', 
    sub {
        my $result = shift;
        ok $result, "Got resolved IPs";
    Mojo::IOLoop->singleton->stop;
});

Mojo::IOLoop->singleton->start;
