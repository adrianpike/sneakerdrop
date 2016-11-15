require 'spec_helper'

require 'json'
require 'sneakerdrop/message_payload'

describe 'a message payload' do

  it 'should raise on bad versions' do
    payload = {
      v: 'hey friends'
    }.to_json

    mp = Sneakerdrop::MessagePayload.new(payload)

    expect {
      msg = mp.to_message
    }.to raise_exception Sneakerdrop::InvalidMessageVersion

  end

  describe 'with a valid broadcast payload' do
    let :payload do
      {     
        v: 0x00,
        t: 'b',
        c: {
          b: File.read(File.join(File.dirname(__FILE__), 'fixtures', 'lorem_ipsum.txt')),
          i: 'random',
          ts: '11221985'
        },
        sg: File.read(File.join(File.dirname(__FILE__), 'fixtures', 'lorem_ipsum.txt.asc')),
        s: File.read(File.join(File.dirname(__FILE__), 'fixtures', 'keys', 'rspec.pub')),
      }
    end

    it 'should convert broadcasts to trusted Messages' do
      mp = Sneakerdrop::MessagePayload.new(payload.to_json)
      msg = mp.to_message

      expect(msg).to be
      expect(msg.type).to eql :broadcast
      expect(msg.body).to eql "Lorem Ipsum\n"
      expect(msg.sender.email).to eql 'rspec@adrianpike.com'
      expect(msg.trusted).to eql true
    end

    it 'should convert a bunk broadcast to an untrusted message' do
      bunk_payload = payload
      bunk_payload[:c][:b] = 'This is a totally valid message. trust me.'

      mp = Sneakerdrop::MessagePayload.new(bunk_payload.to_json)
      msg = mp.to_message

      expect(msg.trusted).to eql false
    end

    it 'should convert a funky sender to an untrusted message' do
      bunk_payload = payload
      bunk_payload[:s] = 'spoopy sender'

      mp = Sneakerdrop::MessagePayload.new(bunk_payload.to_json)

      expect {
        msg = mp.to_message
      }.to raise_error(Sneakerdrop::InvalidSender)
    end

    it 'should throw untrusted on timestamp munging' do
      bunk_payload = payload
      bunk_payload[:c][:ts] = 'trust in me.'

      mp = Sneakerdrop::MessagePayload.new(bunk_payload.to_json)
      msg = mp.to_message

      expect(msg.trusted).to eql false
    end

    it 'should throw untrusted on id munging' do
      bunk_payload = payload
      bunk_payload[:c][:i] = 'trust in me.'

      mp = Sneakerdrop::MessagePayload.new(bunk_payload.to_json)
      msg = mp.to_message

      expect(msg.trusted).to eql false
    end

    it 'should serialize back out to the same JSON' do
      mp = Sneakerdrop::MessagePayload.new(payload.to_json)
      message = mp.to_message

      json = Sneakerdrop::MessagePayload.json_from_message(message)

      comparison = JSON.parse(payload.to_json)
      parsed = JSON.parse(json)

      expect(parsed).to include(comparison)
    end
  end

  describe 'with a valid message payload' do
    let :payload do
      {     
        v: 0x00,
        t: 'm',
        c: {
          b: File.read(File.join(File.dirname(__FILE__), 'fixtures', 'lorem_to_rspec.txt.asc')),
          i: 'random',
          ts: Time.now
        },
        s: File.read(File.join(File.dirname(__FILE__), 'fixtures', 'keys', 'rspec.pub')),
      }
    end

    it 'should decrypt itself and become a Message if its a gpg-encrypted JSON message for us' do
      mp = Sneakerdrop::MessagePayload.new(payload.to_json)
      msg = mp.to_message
      
      expect(msg).to be
      expect(msg.type).to eql :message
      expect(msg.body).to eql "Lorem Ipsum\n"
      expect(msg.sender.email).to eql 'rspec@adrianpike.com'
      expect(msg.trusted).to eql true
    end

    it 'should be invisible and not decrypt if its a gpg message not for us' do
      bunk_payload = payload
      bunk_payload[:c][:b] = File.read(File.join(File.dirname(__FILE__), 'fixtures', 'lorem_to_adrian.asc'))
 
      mp = Sneakerdrop::MessagePayload.new(bunk_payload.to_json)
      msg = mp.to_message

      expect(msg).to be
      expect(msg.body).to_not eql "Lorem"
      expect(msg.sender.email).to eql 'rspec@adrianpike.com'
      expect(msg.visible).to eql false
    end

    it 'should serialize back out for Messages to us' do
      mp = Sneakerdrop::MessagePayload.new(payload.to_json)
      msg = mp.to_message
     
      json = Sneakerdrop::MessagePayload.json_from_message(msg)
 
      comparison = JSON.parse(payload.to_json)
      parsed = JSON.parse(json)

      expect(parsed).to include(comparison)
    end

    it 'should serialize back out for messages not to us' do
      bunk_payload = payload
      bunk_payload[:c][:b] = File.read(File.join(File.dirname(__FILE__), 'fixtures', 'lorem_to_adrian.asc'))

      mp = Sneakerdrop::MessagePayload.new(bunk_payload.to_json)
      msg = mp.to_message
      expect(msg.body).to_not include "Lorem"

      json = Sneakerdrop::MessagePayload.json_from_message(msg)

      expect(json).to_not include "Lorem"

      comparison = JSON.parse(bunk_payload.to_json)
      parsed = JSON.parse(json)

      expect(parsed).to include(comparison)
    end
 
    it 'should assume no type is a message' do
      munged_payload = payload
      munged_payload.delete(:t)

      mp = Sneakerdrop::MessagePayload.new(munged_payload.to_json)
      msg = mp.to_message
      
      expect(msg).to be
      expect(msg.type).to eql :message
    end

    it 'should be expirable'
    it 'should expire after a year no matter what'
  end

  describe 'a message read receipt' do
    it 'should verify signatures'
  end

end
