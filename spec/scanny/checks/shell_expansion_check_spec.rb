require File.expand_path(File.dirname(__FILE__) + '/../../spec_helper')

describe Scanny::Checks::ShellExpansionCheck do
  before(:each) do
    @scanny = Scanny::Core::Runner.new(Scanny::Checks::ShellExpansionCheck.new)
  end

  it "should not report regular method calls" do
    content = <<-EOT
      foo
    EOT

    @scanny.check_content(content)
    errors = @scanny.errors

    errors.should be_empty
  end

  it "should report \"exec\" calls" do
    content = <<-EOT
      exec
    EOT

    @scanny.check_content(content)
    errors = @scanny.errors

    errors.size.should == 1
    errors[0].to_s.should == "dummy-file.rb:2 - The \"exec\" method can pass the executed command through shell exapnsion."
  end

  it "should report \"system\" calls" do
    content = <<-EOT
      system
    EOT

    @scanny.check_content(content)
    errors = @scanny.errors

    errors.size.should == 1
    errors[0].to_s.should == "dummy-file.rb:2 - The \"system\" method can pass the executed command through shell exapnsion."
  end
end

