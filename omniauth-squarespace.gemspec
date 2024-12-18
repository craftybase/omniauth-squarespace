# -*- encoding: utf-8 -*-
require File.expand_path('../lib/omniauth-squarespace/version', __FILE__)

Gem::Specification.new do |gem|
  gem.name        = "omniauth-squarespace"
  gem.version     = OmniAuth::SQUARESPACE::VERSION
  gem.authors     = ["Cristhian Ferreira"]
  gem.email       = ["cristhian@codemera.com"]
  gem.homepage    = ""
  gem.summary     = %q{OmniAuth strategy for SQUARESPACE }
#   gem.description = %q{OmniAuth strategy for squarespace, see https://github.com/squarespace/omniauth-squarespace for examples and more information.}
  gem.license = 'MIT'

  gem.files         = Dir['lib/**/*.rb']
  gem.require_paths = ['lib']

  gem.add_dependency 'omniauth', '~> 2.1'
  gem.add_dependency 'omniauth-oauth2', '~> 1.1'
  gem.add_development_dependency 'rspec', '~> 2.7'
  gem.add_development_dependency 'rack-test'
  gem.add_development_dependency 'simplecov'
  gem.add_development_dependency 'webmock'

end