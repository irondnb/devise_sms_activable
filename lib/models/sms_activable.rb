require "devise_sms_activable/hooks"

module Devise
  module Models
    # SmsActivable is responsible to verify if an account is already confirmed to
    # sign in, and to send sms with confirmation instructions.
    # Confirmation instructions are sent to the user phone after creating a
    # record and when manually requested by a new confirmation instruction request.
    #
    # == Options
    #
    # Confirmable adds the following options to devise_for:
    #
    #   * +sms_confirm_within+: the time you want to allow the user to access his account
    #     before confirming it. After this period, the user access is denied. You can
    #     use this to let your user access some features of your application without
    #     confirming the account, but blocking it after a certain period (ie 7 days).
    #     By default confirm_within is 0 days, so the user must confirm before entering.
    #     If you want to allow user to use parts of the site and block others override
    #     sms_confirmation_required? and check manually on selected pages using the
    #     require_sms_activated! helper or sms_confirmed? property on record
    #
    # == Examples
    #
    #   User.find(1).sms_confirm!      # returns true unless it's already confirmed
    #   User.find(1).sms_confirmed?    # true/false
    #   User.find(1).send_sms_token # manually send token
    #
    module SmsActivable
      extend ActiveSupport::Concern

      # == Constants ============================================================

      FIRST_SMS_INTERVAL = 60.freeze
      SECOND_SMS_INTERVAL = 600.freeze
      THIRD_SMS_INTERVAL = 3600.freeze

      # Confirm a user by setting it's sms_confirmed_at to actual time. If the user
      # is already confirmed, add en error to email field
      def confirm_sms!
        unless_sms_confirmed do
          self.sms_confirmation_token = nil
          self.sms_confirmed_at = Time.now
          save(:validate => false)
        end
      end

      # Verifies whether a user is sms-confirmed or not
      def confirmed_sms?
        !!sms_confirmed_at
      end

      # Send confirmation token by sms
      def send_sms_token
        if phone?
          if sms_confirmation_token.nil? || !confirmation_sms_period_valid?
            generate_sms_token!
          end
          if allowed_to_send?
            ::Devise.sms_sender.send_sms(phone, I18n.t(:"devise.sms_activations.sms_body", sms_confirmation_token: self.sms_confirmation_token, default: self.sms_confirmation_token))
            increment!(:confirmation_sms_count)
          else
            false
          end
        else
          invalidate_sms_confirmation_keys(:no_phone_associated)
        end
      end

      # Resend sms confirmation token. This method does not need to generate a new token.
      def resend_sms_token
        unless_sms_confirmed { send_sms_token }
      end

      # Overwrites active_for_authentication? from Devise::Models::Activatable for sms confirmation
      # by verifying whether a user is active to sign in or not. If the user
      # is already confirmed, it should never be blocked. Otherwise we need to
      # calculate if the confirm time has not expired for this user.

      def active_for_authentication?
        super && (!sms_confirmation_required? || confirmed_sms? || confirmation_sms_period_valid?)
      end

      # The message to be shown if the account is inactive.
      def inactive_message
        sms_confirmation_required? && !confirmed_sms? ? :unconfirmed_sms : super
      end

      # If you don't want confirmation to be sent on create, neither a code
      # to be generated, call skip_sms_confirmation!
      def skip_sms_confirmation!
        self.sms_confirmed_at = Time.now
      end

      protected

      # Checks if the confirmation token can be send.
      def allowed_to_send?
        return true if confirmation_sms_count.zero?

        elapsed_time_delta = last_confirmation_sms_time_elapsed

        if confirmation_sms_count == 1 && elapsed_time_delta < FIRST_SMS_INTERVAL
          errors.add(:base, :try_later, count: (FIRST_SMS_INTERVAL - elapsed_time_delta))
          false
        elsif confirmation_sms_count == 2 && elapsed_time_delta < SECOND_SMS_INTERVAL
          errors.add(:base, :try_later, count: (SECOND_SMS_INTERVAL - elapsed_time_delta))
          false
        elsif confirmation_sms_count == 3 && elapsed_time_delta < THIRD_SMS_INTERVAL
          errors.add(:base, :try_later, count: (THIRD_SMS_INTERVAL - elapsed_time_delta))
          false
        elsif confirmation_sms_count > 3
          errors.add(:base, :too_many_tries, value: confirmation_sms_count)
          false
        else
          true
        end
      end

      def last_confirmation_sms_time_elapsed
        (Time.current - confirmation_sms_sent_at).round(1)
      end

      # Callback to overwrite if an sms confirmation is required or not.
      def sms_confirmation_required?
        !confirmed_sms?
      end

      # Checks if the confirmation for the user is within the limit time.
      # We do this by calculating if the difference between today and the
      # confirmation sent date does not exceed the confirm in time configured.
      # Confirm_in is a model configuration, must always be an integer value.
      #
      # Example:
      #
      #   # sms_confirm_within = 1.day and sms_confirmation_sent_at = today
      #   confirmation_period_valid?   # returns true
      #
      #   # sms_confirm_within = 5.days and sms_confirmation_sent_at = 4.days.ago
      #   confirmation_period_valid?   # returns true
      #
      #   # sms_confirm_within = 5.days and sms_confirmation_sent_at = 5.days.ago
      #   confirmation_period_valid?   # returns false
      #
      #   # sms_confirm_within = 0.days
      #   confirmation_period_valid?   # will always return false
      #
      def confirmation_sms_period_valid?
        confirmation_sms_sent_at && confirmation_sms_sent_at.utc >= self.class.sms_confirm_within.ago
      end

      # Checks whether the record is confirmed or not, yielding to the block
      # if it's already confirmed, otherwise adds an error to email.
      def unless_sms_confirmed
        if !confirmed_sms?
          invalidate_sms_confirmation_keys(:sms_already_confirmed)
        else
          yield
        end
      end

      # Generates a new random token for confirmation, and stores the time
      # this token is being generated
      def generate_sms_token
        self.sms_confirmed_at = nil
        self.sms_confirmation_token = self.class.sms_confirmation_token
        self.confirmation_sms_sent_at = Time.now.utc
      end

      def generate_sms_token!
        generate_sms_token && save(validate: false)
      end

      def invalidate_sms_confirmation_keys(error)
        self.class.sms_confirmation_keys.each do |key|
          errors.add(key, error)
        end
        false
      end

      module ClassMethods
        # Attempt to find a user by it's email. If a record is found, send a new
        # sms token instructions to it. If not user is found, returns a new user
        # with an email not found error.
        # Options must contain the user email
        def send_sms_token(attributes = {})
          sms_confirmable = find_or_initialize_with_errors(sms_confirmation_keys, attributes, :not_found)
          sms_confirmable.resend_sms_token if sms_confirmable.persisted?
          sms_confirmable
        end

        # Find a user by it's sms confirmation token and try to confirm it.
        # If no user is found, returns a new user with an error.
        # If the user is already confirmed, create an error for the user
        # Options must have the sms_confirmation_token
        def confirm_by_sms_token(sms_confirmation_token)
          sms_confirmable = find_or_initialize_with_error_by(:sms_confirmation_token, sms_confirmation_token)

          if sms_confirmable.persisted?
            unless sms_confirmable.sms_period_valid?
              sms_confirmable.errors.add(:sms_confirmation_token, :expired)
              return sms_confirmable
            end
            sms_confirmable.confirm_sms!
          end
          sms_confirmable
        end

        # Generates a small token that can be used conveniently on SMS's.
        # The token is 5 chars long and uppercased.

        def generate_small_token(column)
          loop do
            token = Devise.friendly_token[0, 5].upcase
            break token unless to_adapter.find_first({column => token})
          end
        end

        # Generate an sms token checking if one does not already exist in the database.
        def sms_confirmation_token
          generate_small_token(:sms_confirmation_token)
        end

        Devise::Models.config(self, :sms_confirm_within, :sms_confirmation_keys)
      end
    end
  end
end
