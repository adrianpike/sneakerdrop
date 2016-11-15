require 'simplecov'
SimpleCov.start

require 'gpgme'
GPGME::Engine.home_dir = 'spec/fixtures/keyring'
