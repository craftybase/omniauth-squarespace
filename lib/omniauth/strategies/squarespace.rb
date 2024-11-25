require "omniauth/strategies/oauth2"

module OmniAuth
  module Strategies
    class Squarespace < OmniAuth::Strategies::OAuth2
      VERSION = 1

      option :provider_ignores_state, true
      option :name, "squarespace"
      option :client_options, {
        site: "https://www.squarespace.com/",
        authorize_url: "https://login.squarespace.com/api/#{VERSION}/login/oauth/provider/authorize",
        token_url: "https://login.squarespace.com/api/#{VERSION}/login/oauth/provider/tokens",
        # profile_url: "https://api.squarespace.com/#{VERSION}/profiles/?filter=isCustomer,true;hasAccount,true",
        redirect_uri: "https://craftybase.com/auth/squarespace/callback",
        website_scope: 'website.orders.read,website.transactions.read,website.inventory,website.inventory.read,website.products.read',
        # profile_scope: 'profile.read', #profile scope cannot be requested alongside website scope, from error
        state: 'abcd1234',
        access_type: 'offline',
      }

      credentials do
        hash = {"token": access_token.token}
        hash["refresh_token"] = access_token.refresh_token if access_token.refresh_token
        hash["expires_at"] = access_token.expires_at if access_token.expires?
        hash["expires"] = access_token.expires?
        hash
      end

      def request_phase
        redirect client.auth_code.authorize_url(
          {
            client_id: client.id,
            redirect_uri: client.options[:redirect_uri],
            scope: client.options[:website_scope],
            state: client.options[:state],
            access_type: client.options[:access_type]
          }
        )
      end

      def build_access_token
        ::OAuth2::AccessToken.from_hash(
          client,
          JSON.parse(
            Faraday.new(
              headers: {
                Accept: 'application/json',
                Authorization: "Basic #{Base64.strict_encode64("#{client.id}:#{client.secret}").strip}"
              }
            ).post(
              client.token_url,
              {
                grant_type: 'authorization_code',
                redirect_uri: client.options[:redirect_uri],
                code: request.params['code']
              }
            ).body
          ).symbolize_keys.merge({ expires_in: 10.minutes })
        )
      end
    end
  end
end
