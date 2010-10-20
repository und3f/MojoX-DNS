#!/usr/bin/env perl

use 5.008007;

use strict;
use warnings;

use ExtUtils::MakeMaker;

WriteMakefile(
    NAME              => 'MojoX::DNS',
    VERSION_FROM      => 'lib/MojoX/DNS.pm',
    ABSTRACT        => 'The DNS In A Box!',
    AUTHOR          => 'Sergey Zasenko',
    PREREQ_PM   => {
        'Mojo'      => 0
    },
    test            => { TESTS => 't/*.t t/*/*.t' },
);
