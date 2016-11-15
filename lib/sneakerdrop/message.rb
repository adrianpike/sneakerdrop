require 'securerandom'
require 'json'
require 'gpgme'

require 'byebug'

module Sneakerdrop

  # TODO: class GpgMessage
  class Message
    
    attr_accessor :type, 
      :sender, 
      :raw_body, 
      :expires_at, 
      :signature,
      :timestamp, 
      :recipient,
      :visible,
      :id

    def generate_id!
      @id ||= SecureRandom.uuid
    end

    def generate_timestamp!
      @timestamp ||= Time.now.to_i
    end

    def body 
      case type
        when :broadcast
          raw_body
        when :message
          begin
            @body ||= decrypted_raw_body
          rescue GPGME::Error::DecryptFailed
            @visible = false
            @body ||= raw_body
          end
        else
          ''
      end
    end
 
    def decrypted_raw_body
      crypto = GPGME::Crypto.new
      out = crypto.decrypt(raw_body)
      out.to_s
    end

    def body=(content)
      case type
        when :broadcast
          @raw_body = content
        when :message
          crypto = GPGME::Crypto.new(armor: true)

          out = crypto.encrypt(content, recipients: recipient)
          @raw_body = out.to_s
        else

      end
    end

    def signature
      @signature ||= begin
        raise StandardError, 'Need to set timestamp and id before calling .signature!' unless id and timestamp
        crypto = GPGME::Crypto.new armor: true
        crypto.sign data_to_sign, mode: GPGME::SIG_MODE_DETACH
      end
    end

    def data_to_sign
      [id, @raw_body, timestamp].join(':')
    end

    def trusted
      crypto = GPGME::Crypto.new armor: true
      
      valid = true 

      case type
      when :message
      when :broadcast
        begin
          entered = false
          crypto.verify(signature, signed_text: data_to_sign) do |signature|
            # This is a strange hack - TODO: revisit
            entered = true

            # and it == "sender"
            valid = valid && signature.valid?
          end
          valid = valid && entered
        rescue GPGME::Error::NoData
          valid = false
        end
      end

      valid 
    end

  end
end
