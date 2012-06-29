module Scanny
  module Checks
    class SendFileCheck < Check
      def pattern
        [
          pattern_send,
          pattern_send_file_with_params
        ].join("|")
      end

      def check(node)
        if Machete.matches?(node, pattern_send)
          issue :medium, warning_message, :cwe => [115, 200]
        else
          issue :high, warning_message, :cwe => 201
        end
      end

      private

      def warning_message
        "Sending file to client can lead to" +
        "MIME-Sniffing or info disclosure issue"
      end

      def pattern_send
        <<-EOT
        SendWithArguments<
          name = :send_file | :send_data,
          arguments = ActualArguments<
            array = [
              any*,
              HashLiteral<
                array = [
                  any*,
                  SymbolLiteral<value   = :disposition>,
                  StringLiteral<string  = "inline">,
                  any*
                ]
              >,
              any*
            ]
          >
        >
        EOT
      end

      def pattern_send_file_with_params
        <<-EOT
          SendWithArguments<
            name = :send_file,
            arguments = ActualArguments<
              array = [
                any*,
                SendWithArguments<
                  name = :[],
                  receiver = Send<name = :params>
                >,
                any*
              ]
            >
          >
        EOT
      end
    end
  end
end
