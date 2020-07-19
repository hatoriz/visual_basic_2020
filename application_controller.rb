# frozen_string_literal: true

module V2
  class ApplicationController < ActionController::API
    include Localization
    include V2::PaginationParameters
    include V2::ClientVersion
    include The1Idm::V2::Authentication
    include ActionController::HttpAuthentication::Basic::ControllerMethods

    # The rescue_from block goes from bottom to top, if we put the parent error class at the bottom
    # it will always go there, so to prevent that the parent error class has to put on top the child error class
    # https://apidock.com/rails/ActiveSupport/Rescuable/ClassMethods/rescue_from
    # eg: StandardError -> The1::Mulesoft::Errors::Error -> The1::Mulesoft::Errors::ExpiredTokenError
    # TODO: Find a way to notify exception.
    rescue_from StandardError do |e|
      Utils::ErrorReporter.call(e)

      render_error(detail: I18n.t('errors.generic'),
                   meta: {
                     class: e.class.name,
                     message: e.message,
                     backtrace: e.backtrace
                   },
                   status: :internal_server_error)
    end

    rescue_from The1::T1P::Errors::Error,
                The1::Mulesoft::Errors::Error,
                The1::AEM::Errors::Error,
                The1::CGMulesoft::Errors::Error,
                The1::API::Errors::MalformedResponseError do |e|
      Utils::ErrorReporter.call(e,
                                tags: {
                                  from: :upstream,
                                  upstream_name: e.attributes[:origin]
                                },
                                expected: true,
                                only: :new_relic)

      render_error(source: { parameter: e.attributes[:origin] },
                   detail: e.message,
                   code: e.attributes[:code],
                   meta: {
                     request: e.attributes[:request],
                     response: e.attributes[:response]
                   })
    end

    rescue_from ActiveRecord::RecordNotFound do |e|
      render_error(detail: e.message, status: :not_found)
    end

    rescue_from The1::API::Errors::RecordNotFound do |e|
      Utils::ErrorReporter.call(e,
                                tags: {
                                  from: :upstream,
                                  upstream_name: e.attributes[:origin]
                                },
                                expected: true,
                                only: :new_relic)

      render_error(detail: e.message, status: :not_found)
    end

    rescue_from The1::API::Errors::ExpiredTokenError do
      render_error(detail: I18n.t('idm.v2.errors.token.expired'), status: :unauthorized)
    end

    rescue_from The1::API::Errors::UnauthorizedError, The1::API::Errors::InvalidTokenError do
      render_error(detail: I18n.t('idm.v2.errors.token.invalid'), status: :unauthorized)
    end

    rescue_from The1::API::Errors::UnsupportedTypeError do |e|
      render_error(detail: e.message, status: :unprocessable_entity)
    end

    rescue_from The1::API::Errors::UnsupportedTransactionChannelError do |e|
      render_error(detail: e.message, status: :unprocessable_entity)
    end

    if Rails.env.production?
      rescue_from Rack::Timeout::RequestTimeoutException do |e|
        Utils::ErrorReporter.call(e)

        render_error(source: { parameter: request.original_url },
                     detail: e.message)
      end
    end

    def customer_access_token_attribute
      { customer_access_token: customer_access_token }
    end

    def transaction_channel_attribute
      { transaction_channel: request.headers[:'Transaction-Channel'] }
    end

    def http_basic_authenticate
      authenticate_or_request_with_http_basic do |username, password|
        username == ENV.fetch('BASIC_AUTHENTICATION_USERNAME') && password == ENV.fetch('BASIC_AUTHENTICATION_PASSWORD')
      end
    end

    private

    # Render Error Message in json_api format
    def render_error(detail:, source: nil, meta: nil, status: :unprocessable_entity, code: nil)
      errors = [
        {
          source: source,
          detail: detail,
          code: code,
          meta: meta
        }.compact
      ]

      render json: { errors: errors }, status: status
    end
  end
end
