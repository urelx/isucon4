require_relative './app.rb'
require 'stackprof' if ENV['ENABLE_STACKPROF']

if ENV['ENABLE_STACKPROF']
  is_stackprof         =  ENV['ENABLE_STACKPROF'].to_i.nonzero?
  stackprof_mode       = (ENV['STACKPROF_MODE']       || :cpu).to_sym
  stackprof_interval   = (ENV['STACKPROF_INTERVAL']   || 1000).to_i
  stackprof_save_every = (ENV['STACKPROF_SAVE_EVERY'] || 100 ).to_i
  stackprof_path       =  ENV['STACKPROF_PATH']       || 'tmp'
  use StackProf::Middleware, enabled:    is_stackprof,
                             mode:       stackprof_mode,
                             raw:        true,
                             interval:   stackprof_interval,
                             save_every: stackprof_save_every,
                             path:       stackprof_path
end

run Isucon4::App
