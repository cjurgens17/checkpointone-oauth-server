from webauthn import (
    base64url_to_bytes,
    generate_registration_options,
    options_to_json,
    verify_registration_response,
)

################
# Reference: https://github.com/duo-labs/py_webauthn/blob/master/examples/registration.py
################

#Wrapper on generate_registration_options
def start_simple_registration_options(
    rp_id, rp_name, user_name, user_handle, challenge
):
    simple_registration_options = generate_registration_options(
        rp_id=rp_id,
        rp_name=rp_name,
        user_name=user_name,
        user_handle=user_handle,
        challenge=challenge,
    )

    to_json = options_to_json(simple_registration_options)

    print("\n[Registration Options - Simple]")
    print(options_to_json(to_json))
    return to_json
    

# Wrapper on Registration Response Verification
def end_registration_verification(credential, expected_challenge,expected_rp_id, expected_origin,require_user_verification=False):
    #         REQUIRED:
    #         - `credential`: The value returned from `navigator.credentials.create()`. Can be either a
    #           stringified JSON object, a plain dict, or an instance of RegistrationCredential
    #         - `expected_challenge`: The challenge passed to the authenticator within the preceding
    #           registration options.
    #         - `expected_rp_id`: The Relying Party's unique identifier as specified in the preceding
    #           registration options.
    #         - `expected_origin`: The domain, with HTTP protocol (e.g. "https://domain.here"), on which
    #           the registration should have occurred. Can also be a list of expected origins.
    if not isinstance(expected_challenge, bytes):
        base64url_to_bytes(expected_challenge)
    registration_verification = verify_registration_response(
    
    credential=credential,
    expected_challenge=expected_challenge,
    expected_origin=expected_origin,
    expected_rp_id=expected_rp_id,
    require_user_verification=require_user_verification,
    )

    print("\n[Registration Verification - None]")
    print(registration_verification)