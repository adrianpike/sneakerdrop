require 'sneakerdrop'

module Sneakerdrop
  PREAMBLE = "== SNEAKERDROP #{PROTOCOL_VERSION} =="
  POSTAMBLE = "== PORDREKAENS =="

  class Events 

    def self.read(stream)
      buf = ""
      in_message = false

      while consume = stream.read(1024)
        buf += consume
        if start = buf.index(Sneakerdrop::PREAMBLE)
          in_message = true
          if stop = buf.index(Sneakerdrop::POSTAMBLE)
            msg_start = start + Sneakerdrop::PREAMBLE.length
            msg_length = stop - msg_start
            message = buf.slice(msg_start, msg_length)
            yield(message)
            buf = buf.slice(stop + Sneakerdrop::POSTAMBLE.length .. buf.length)
          end
        end
      end
          
    end

  end

end

