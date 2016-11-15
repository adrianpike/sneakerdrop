require 'sneakerdrop/message'
require 'sneakerdrop/sender'

module Sneakerdrop
  class NoJson < StandardError; end
  class InvalidMessageVersion < StandardError; end
  class MalformedMessage < StandardError; end


  # A Payload encapsulates the logic to serialize/deserialize, and encrypt/decrypt
  # Message objects.

  class MessagePayload

    def initialize(json)
      raise NoJson, 'No JSON sent to payload' unless json

      @body = JSON.parse(json)
    end

    def to_message
      raise InvalidMessageVersion unless @body['v'] == 0x00
      raise MalformedMessage unless @body['c']

      msg = Sneakerdrop::Message.new

      msg.sender = Sneakerdrop::Sender.new(@body['s'])
      msg.type = case @body['t']
      when 'b'
        :broadcast
      when 'r'
        :read_receipt
      when nil, 'm'
        :message
      end

      msg.raw_body = @body['c']['b']
      msg.signature = @body['sg']
      msg.timestamp = @body['c']['ts']
      msg.id = @body['c']['i']
 
      msg
    end

    def self.json_from_message(message)
      type = case message.type
             when :broadcast
               'b'
             when :read_receipt
               'r'
             else
               'm'
             end

      {
        's' => message.sender.armored_key,
        'v' => 0x00,
        't' => type,
        'c' => {
          'ts' => message.timestamp,
          'b' => message.raw_body,
          'i' => message.id
        },
        'sg' => message.signature
      }.to_json
    end

  end
end
