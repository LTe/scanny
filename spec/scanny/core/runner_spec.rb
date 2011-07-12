require File.expand_path(File.dirname(__FILE__) + '/../../spec_helper')

describe Scanny::Core::Runner do
  
  describe "given a custom config file" do
    before do
      @runner = Scanny::Core::Runner.new
      @runner.config= File.expand_path(File.dirname(__FILE__) + '/../scanny.yml')
    end
    
    it "uses check from it" do
      # @runner.check_file(File.expand_path(File.dirname(__FILE__) + '/../fixtures/test_class.rb'))
      content = <<-RUBY
        class TestClass

          def METHOD

          end
        end
      RUBY
      @runner.check_content(content)
      @runner.errors.should be_empty
    end
  end
end
