require 'digest/sha1'
require 'base64'

module QcloudRuby
  class Configuration
    attr_accessor :base_host, :ssl, :path, :secret_id, :secret_key

    def initialize
      @base_host = 'tencentcloudapi.com'
      @path      = '/'
      @ssl       = true
    end

    def protocol
      ssl? ? 'https' : 'http'
    end

    alias_method :ssl?, :ssl
  end
end
