require 'spec_helper'

require 'sneakerdrop/ledger'
require 'sneakerdrop/events'

describe 'the ledger' do

  before(:each) do
    @temp_ledger_path = File.join(File.dirname(__FILE__), 'tmp', 'test_ledger.snk')

    begin
      File.delete(@temp_ledger_path)
    rescue Errno::ENOENT
    end
  end

  it 'should be initializable with no path and get an empty ledger' do
    ledger = Sneakerdrop::Ledger.new(path: @temp_ledger_path)

    expect(ledger.messages.length).to eql 0
  end

  it 'shuld be initializable with a path to an existing ledger' do
    ledger = Sneakerdrop::Ledger.new(path: File.join(File.dirname(__FILE__), 'fixtures', 'example.snk'))

    expect(ledger.messages.length).to eql 5
    msg = ledger.messages[ledger.messages.keys.first]

    expect(msg.body).to eql "Lorem Ipsum\n"
    expect(msg.trusted).to eql true
  end

  it 'should allow broadcast Messages to be added, saved, and loaded', focus: true do
    ledger = Sneakerdrop::Ledger.new(path: @temp_ledger_path)
    expect(ledger.messages.length).to eql 0
  
    msg = Sneakerdrop::Message.new
    msg.type = :broadcast
    msg.body = 'Yo.'
    msg.sender = Sneakerdrop::Sender.ourselves

    ledger.record(msg)

    expect(ledger.messages.length).to eql 1
    
    msg = ledger.messages[ledger.messages.keys.first]
    expect(msg.body).to eql 'Yo.'
    expect(msg.id).to be
    expect(msg.trusted).to eql true
    expect(msg.sender.email).to eql('rspec@adrianpike.com')

    ledger.save!

    ledger2 = Sneakerdrop::Ledger.new(path: @temp_ledger_path)
    expect(ledger2.messages.length).to eql ledger.messages.length
  
    ledger.messages.each do |key, msg|
      compare = ledger2.messages[key]
      
      [:body, :id, :trusted].each do |key|
        expect(compare.send(key)).to eql(msg.send(key))
      end

      expect(compare.sender.email).to eql(msg.sender.email)
    end
  end

  it 'should allow directed Message additions to be added, saved, and loaded', focus: true do
    ledger = Sneakerdrop::Ledger.new(path: @temp_ledger_path)
    expect(ledger.messages.length).to eql 0
    msg = Sneakerdrop::Message.new
    msg.type = :message
    msg.recipient = 'rspec2@adrianpike.com'

    # Should raise if we don't have a recipient yet.
    msg.body = 'Yo.'

    msg.sender = Sneakerdrop::Sender.ourselves

    ledger.record(msg)

    expect(ledger.messages.length).to eql 1
    
    msg = ledger.messages[ledger.messages.keys.first]
    expect(msg.body).to eql 'Yo.'
    expect(msg.id).to be
    expect(msg.trusted).to eql true
    expect(msg.sender.email).to eql('rspec@adrianpike.com')
    ledger.save!

    ledger2 = Sneakerdrop::Ledger.new(path: @temp_ledger_path)
    expect(ledger2.messages.length).to eql ledger.messages.length
  
    ledger.messages.each do |key, msg|
      compare = ledger2.messages[key]
      
      [:body, :id, :trusted].each do |key|
        expect(compare.send(key)).to eql(msg.send(key))
      end

      expect(compare.sender.email).to eql(msg.sender.email)
    end
  end

  it 'should not allow message ID spoofing on broadcasts'
  it 'should not allow timestamp ID spoofing on broadcasts'
  it 'should discard duplicate messages'
  it 'should persist unknown MessagePayload versions'
  it 'should persist messages not for us'
  it 'should merge two ledgers'
  it 'should not allow merged ledgers with spoofed IDs to have data loss'
  it 'should expire messages'
  it 'shoould apply read receipts to messages'
  it 'should remove read receipts when its companion message expires'
  it 'should allow for noise in the preambles'

end
