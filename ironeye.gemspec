# frozen_string_literal: true

require_relative "lib/ironeye"

Gem::Specification.new do |spec|
  spec.name = "ironeye"
  spec.version = IronEye::VERSION
  spec.authors = ["Direct Softworks"]
  spec.summary = "Official Ruby client for the IronEye document intelligence and collection API."
  spec.homepage = "https://ironeye.org"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.1"

  spec.metadata = {
    "documentation_uri" => "https://ironeye.org/docs/sdk/ruby",
    "homepage_uri" => spec.homepage,
    "source_code_uri" => "https://github.com/IronEyeAPI/ironeye-ruby",
    "bug_tracker_uri" => "https://github.com/IronEyeAPI/ironeye-ruby/issues",
    "rubygems_mfa_required" => "true"
  }

  # Net::HTTP and JSON are enough. A client library that drags a gem tree behind
  # it is a client library that dictates the host application's dependencies.
  spec.files = Dir["lib/**/*.rb", "README.md", "LICENSE"]
  spec.require_paths = ["lib"]
end
