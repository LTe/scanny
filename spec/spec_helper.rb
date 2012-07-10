require "scanny"

Dir[File.dirname(__FILE__) + "/support/**/*.rb"].each {|f| require f}

RSpec.configure do |c|
  c.include CheckSpecHelpers
  c.include ConstSpecHelpers
  c.include Aruba::Api
  c.color_enabled = true
end
