module Sneakerdrop
  
  class InvalidSender < StandardError; end

  class Sender

    attr_accessor :key

    def initialize(armored_key)
      # TODO: once we run in our own sandboxed GPG dir
      if armored_key.is_a?(GPGME::Key)
        @key = armored_key
      else
        results = GPGME::Key.import(armored_key) # might not be needed

        if results.imports.length == 1
          fingerprint = results.imports.first.fpr
          @key = GPGME::Key.find(:public, fingerprint).first
        else
          raise InvalidSender
        end
      end
    end

    def email
      @key.email
    end

    def armored_key
      @key.export(armor: true).to_s
    end
    
    def self.ourselves
      key = GPGME::Key.find(:secret, ENV['SNEAKERDROP_SENDER'] || '').first
      raise InvalidSender unless key
      self.new(key)
    end
      
  end

end
