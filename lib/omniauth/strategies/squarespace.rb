require "omniauth/strategies/oauth2"

module OmniAuth
  module Strategies
    class Squarespace < OmniAuth::Strategies::OAuth2

      option :name, "squarespace"

      option :client_options, {
        authorize_url: "https://login.squarespace.com/api/1/login/oauth/provider/authorize",
        token_url: "https://login.squarespace.com/api/1/login/oauth/provider/tokens",
        site: "https://www.squarespace.com/"
      }

      def request_phase
        super
      end

      def authorize_params
        super.tap do |params|
          %w[scope client_options].each do |v|
            if request.params[v]
              params[v.to_sym] = request.params[v]
            end
          end
        end
      end

      def callback_url
        options[:redirect_uri] || full_host + script_name + callback_path
      end

      def callback_phase 
        super
      end

      def raw_info
        puts "******raw info*************"
        puts access_token
        puts "******raw info*************"
      end

      def auth_hash
          puts "**********auth hash**********"
          puts params
          puts "**********auth hash end**********"
      end

      # info do
      #   {
      #     name: raw_info["user"]["name"],
      #     bio: raw_info["user"]["bio"],
      #     facebook_profile: raw_info["user"]["facebook_profile"],
      #     twitter_handle: raw_info["user"]["twitter_handle"],
      #     id: raw_info["user"]["id"]
      #   }
      # end

      # uid { raw_info["user"]["id"].to_s }

      # extra do
      #   { raw_info: raw_info }
      # end

      # def raw_info
      #   puts "******************raw_info**********************************"
      #   puts access_token
      #   puts "******************raw_info**********************************"
      #   @raw_info ||= access_token.get("/api/v2/user").parsed
      # end
    end
  end
end

OmniAuth.config.add_camelization "squarespace", "Squarespace"