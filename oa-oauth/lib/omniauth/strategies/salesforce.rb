require 'omniauth/oauth'
#require 'multi_json'

module OmniAuth
  module Strategies
    # Authenticate to Facebook utilizing OAuth 2.0 and retrieve
    # basic user information.
    #
    # @example Basic Usage
    #   use OmniAuth::Strategies::Facebook, 'client_id', 'client_secret'
    class Salesforce < OAuth2
      # @param [Rack Application] app standard middleware application parameter
      # @param [String] client_id the application id as [registered on Facebook](http://www.facebook.com/developers/)
      # @param [String] client_secret the application secret as registered on Facebook
      # @option options [String] :scope ('email,offline_access') comma-separated extended permissions such as `email` and `manage_pages`
      def initialize(app, client_id = nil, client_secret = nil, options = {}, &block)
        options[:response_type] = "code"
        super(app, :salesforce, client_id, client_secret, 
                { :site => 'https://login.salesforce.com/',
                  :authorize_path => "/services/oauth2/authorize"}, options)
      end

      def user_data
        @data ||= MultiJson.decode(@access_token.get('/services/oauth2/token', {:grant_type => "authorization_code"}))
      end
      
      def auth_hash
        OmniAuth::Utils.deep_merge(super, {
          'access_token' => user_data['access_token'],
          'instance_url' => user_data['instance_url'],
          'extra' => {'user_hash' => user_data}
        })
      end
    end
  end
end