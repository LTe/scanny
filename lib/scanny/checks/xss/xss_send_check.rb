module Scanny
  module Checks
    # Checks for send_ methods that are called with :disposition => 'inline'.
    # This can lead to download private file from server or to XSS issue.
    class XssSendCheck < Check
      def pattern
        pattern_send
      end

      def check(node)
        issue :high, warning_message, :cwe => 79
      end

      private

      def warning_message
        "Send file or data to client in \"inline\" mode can lead to XSS issues."
      end

      #medium          CWE-79                  send_file.*:disposition\s*=>\s*\'inline\'
      #medium          CWE-79                  send_data.*:disposition\s*=>\s*\'inline\'
      def pattern_send
        <<-EOT
        SendWithArguments<
          name = :send_file | :send_data,
          arguments = ActualArguments<
            array = [
              HashLiteral<
                array = [
                  SymbolLiteral<value   = :disposition>,
                  StringLiteral<string  = "inline">
                ]
              >
            ]
          >
        >
        EOT
      end
    end
  end
end
