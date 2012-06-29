require "spec_helper"

module Scanny::Checks
  describe SendFileCheck do
    before do
      @runner = Scanny::Runner.new(SendFileCheck.new)
      @message =  "Sending file to client can lead to" +
                  "MIME-Sniffing or info disclosure issue"
      @issue_medium = issue(:medium, @message, [115, 200])
      @issue_high = issue(:high, @message, 201)
    end

    it "reports \"send_file file, :disposition => 'inline'\" correctly" do
      @runner.should check("send_file(file, :disposition => 'inline')").
                      with_issue(@issue_medium)
    end

    it "reports \"send_data file, :disposition => 'inline'\" correctly" do
      @runner.should  check("send_data(file, :disposition => 'inline')").
                      with_issue(@issue_medium)
    end

    it "reports \"send_file params[:file]\" correctly" do
      @runner.should check("send_file(params[:file])").with_issue(@issue_high)
    end
  end
end
