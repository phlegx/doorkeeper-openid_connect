# frozen_string_literal: true

require 'rails_helper'

describe Doorkeeper::OpenidConnect do
  describe '.signing_algorithm' do
    it 'returns the signing_algorithm as an uppercase symbol' do
      expect(subject.signing_algorithm).to eq :RS256
    end
  end

  describe '.signing_key' do
    it 'returns the private key as JWK instance' do
      expect(subject.signing_key).to be_instance_of JWT::JWK::RSA
      expect(subject.signing_key.export[:kid]).to eq 'dad3159bddd1097d73c281254d943fb39e89a52efe3992bc600997c74d2c7756'
    end
  end

  describe '.signing_key_normalized' do
    context 'when signing key is RSA' do
      it 'returns the RSA public key parameters' do
        expect(subject.signing_key_normalized).to eq(
          kty: 'RSA',
          kid: 'dad3159bddd1097d73c281254d943fb39e89a52efe3992bc600997c74d2c7756',
          e:   'AQAB',
          n:   'sjdnSA6UWUQQHf6BLIkIEUhMRNBJC1NN_pFt1EJmEiI88GS0ceROO5B5Ooo9Y3QOWJ_n-u1uwTHBz0HCTN4wgArWd1TcqB5GQzQRP4eYnWyPfi4CfeqAHzQp-v4VwbcK0LW4FqtW5D0dtrFtI281FDxLhARzkhU2y7fuYhL8fVw5rUhE8uwvHRZ5CEZyxf7BSHxIvOZAAymhuzNLATt2DGkDInU1BmF75tEtBJAVLzWG_j4LPZh1EpSdfezqaXQlcy9PJi916UzTl0P7Yy-ulOdUsMlB6yo8qKTY1-AbZ5jzneHbGDU_O8QjYvii1WDmJ60t0jXicmOkGrOhruOptw'
        )
      end
    end

    context 'when signing key is EC' do
      before { configure_ec }

      it 'returns the EC public key parameters' do
        expect(subject.signing_key_normalized).to eq(
          kty: 'EC',
          kid: 'f6e390ea7cfeceece9e522b354fdeec55fe49f9a1d33313402e6339811b1121e',
          crv: 'P-521',
          x:   'AeYVvbl3zZcFCdE-0msqOowYODjzeXAhjsZKhdNjGlDREvko3UFOw6S43g-s8bvVBmBz3fCodEzFRYQqJVI4UFvF',
          y:   'AYJ7GYeBm_Fb6liN53xGASdbRSzF34h4BDSVYzjtQc7I-1LK17fwwS3VfQCJwaT6zX33HTrhR4VoUEUJHKwR3dNs'
        )
      end
    end

    context 'when signing key is HMAC' do
      before { configure_hmac }

      it 'returns the HMAC public key parameters' do
        expect(subject.signing_key_normalized).to eq(
          kty: 'oct',
          kid: 'e10b500c9d99df7ed033d6cf8a9b214bab1b2c65b5a0c5ecabe697303624fedf'
        )
      end
    end
  end
end
