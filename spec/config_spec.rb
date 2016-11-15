require 'spec_helper'

require 'sneakerdrop/sender'

describe 'Sneakerdrop::Sender' do

  it 'should let me change the sender i send as' do
    key = Sneakerdrop::Sender.ourselves
    expect(key.email).to eql 'rspec@adrianpike.com'

    ENV['SNEAKERDROP_SENDER'] = 'rspec2@adrianpike.com'

    key = Sneakerdrop::Sender.ourselves
    expect(key.email).to eql 'rspec2@adrianpike.com'

    ENV.delete('SNEAKERDROP_SENDER')
  end

  it 'should raise if i try to set the sender as el bunko' do
    ENV['SNEAKERDROP_SENDER'] = 'hello.it.me@adrianpike.com'

    expect {
      key = Sneakerdrop::Sender.ourselves
    }.to raise_error(Sneakerdrop::InvalidSender)
    ENV.delete('SNEAKERDROP_SENDER')
  end

end
