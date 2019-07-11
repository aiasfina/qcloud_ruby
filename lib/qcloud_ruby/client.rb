require 'forwardable'
require 'uri'
require 'openssl'
require 'base64'
require 'net/http'

module QcloudRuby
  class Client
    extend Forwardable

    attr_accessor :service_type

    def initialize(&block)
      self.instance_eval(&block)
    end

    def default_params(action)
      params = {
        Action: action,
        SecretId: secret_id,
        Timestamp: timestamp,
        Nonce: nonce
      }
      params
    end

    def gen_data(method, action, other_params)
      params = default_params(action).merge(other_params).sort.to_h
      query_str = URI.encode_www_form(params)
      params.merge!(Signature: sign(method, query_str))
    end

    def request(method: 'POST', action: nil, secret_id: nil, secret_key: nil,  **other_params)
      if secret_id || secret_key
        QcloudRuby.configure do |config|
          config.secret_id = secret_id
          config.secret_key = secret_key
        end
      end

      data = gen_data(method, action, other_params)
      uri = URI(url_with_protocol)

      resp = if method == 'GET'
               uri.query = URI.encode_www_form(data)
               Net::HTTP.get_response(uri)
             else
               Net::HTTP.post_form(uri, data)
             end

      resp
    end

    def timestamp
      Time.now.to_i
    end

    def nonce
      (rand() * 65535).round
    end

    def identity
      "SDK_RUBY_#{::QcloudRuby::VERSION}"
    end

    def host
      "#{service_type}.#{base_host}"
    end

    def url
      "#{host}#{path}"
    end

    def url_with_protocol
      "#{protocol}://#{url}"
    end

    def sign(method, query)
      source = method + url + '?' + query

      Base64.encode64(OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha1'),
                                           secret_key,
                                           source)).strip
    end

    def_delegators :'QcloudRuby.configuration',
      :protocol, :secret_id, :secret_key, :base_host, :path
  end
end
