require 'sneakerdrop/message_payload'
require 'sneakerdrop/message'
require 'fileutils'

module Sneakerdrop
  class Ledger
    
    attr_accessor :messages,
                  :path

    def initialize(opts = {})
      @messages = {}
      @path = opts[:path] || 'ledger.snk'

      @io = File.open(@path, "a+")
      Sneakerdrop::Events.read(@io) do |msg_body|
        payload = Sneakerdrop::MessagePayload.new(msg_body)
        msg = payload.to_message
        next unless msg
        # TODO: ensure message ID isnt spoofed here
        # TODO: cnfigure the response based on paranoia level

        @messages[msg.id] = msg 
      end

    end

    def record(message)
      raise StandardError, 'I only record Messages.' unless message.is_a?(Sneakerdrop::Message) or message.is_a?(Sneakerdrop::Message)
      
      message.generate_timestamp! unless message.timestamp
      message.generate_id! unless message.id

      if @messages[message.id]
        STDERR.puts "Duplicate message received, skipping." if Sneakerdrop::DEBUG
      else
        @messages[message.id] = message
      end
    end

    def save!
      # Because we might break during the save.
      FileUtils.cp @io.path, @io.path + ".bak"

      @io.rewind
      @io.truncate(0)

      @messages.keys.sort.each do |k|
        STDERR.puts "Saving #{k}..."
        
        @io.write(
          Sneakerdrop::PREAMBLE + "\n" +
          MessagePayload.json_from_message(@messages[k]) + "\n" +
          Sneakerdrop::POSTAMBLE + "\n"
        )
      end

      @io.flush

      FileUtils.rm @io.path + ".bak"
    end

  end
end
