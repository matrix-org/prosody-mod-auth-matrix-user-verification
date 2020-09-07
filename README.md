# Prosody Auth Matrix User Verification for Jitsi

Matrix user verification auth for Prosody for Jitsi usage.

## Description

Prosody auth for glue between Jitsi Meet external API and [Matrix user verification service](https://github.com/matrix-org/matrix-user-verification-service)
to handle verifying a given Matrix user exists and that they are in a room that
matches the Jitsi room ID.

```
| -------------- |      | ------------- |     | -------------------- |   | ------- |
| Jitsi Meet     |      | Jitsi/Prosody |     | Matrix User          |   | Synapse |
| external API   |      | (this module) |     | Verification Service |   | ------- |
| -------------- |      | ------------- |     | -------------------- |
        |                      
        |                      
    initialize ------------->  |
                               |
                               |
                          verify data ---------------> |
                                                       |
                                                       |
                                                  verify user and
                                                  room membership ---------> |
                                                                             |
                                                                             |
                                                       | <-------- user and room response   
                                                       |
                                                       |
                               | <---------- verification response
                               |
                               |
        | <-------------- auth response
        |
        |
  join conference
  or denied access                          
```
                            
## Usage

When initializing Jitsi, the Jitsi Meet external API should be initialized with the
following options:

* `roomName`: base64 encoded Matrix room ID to check the user is in
* `jwt`: a JWT token, for example:

```json
{
  "context": {
    "user": {
      "avatar": "https:/gravatar.com/avatar/abc123",
      "name": "John Doe",
      "email": "jdoe@example.com"
    },
    "matrix": {
      "token": "DX81zuBbR1Qt7WGnyiIQYdqbDSm2ECnx",
      "room_id": "!qwertyasdfgh:matrix.org"
    }
  },
  "aud": "jitsi",
  "iss": "issuer",
  "sub": "jitsi.example.com",
  "room": "*"
}
```

For generating the token, note the following:

* `content.user` is optional, will be used for the Jitsi Meet session if given.
* `matrix.token` is an OpenID token from the Matrix C2S API, see [here](https://matrix.org/docs/spec/client_server/r0.6.1#id154).
* `matrix.room_id` should be the Matrix room ID we want to check the user is in. When base64 encoded it must match the Jitsi room ID.
* `aud` can be for example "jitsi", should match Prosody token auth issuers/audience if needed.
* `iss` issuer of the token, must match `app_id` below in Prosody config.
* `sub` should be the Jitsi Meet domain.
* `room` is not used at the moment, a `*` works here.

NOTE! The JWT can be signed with any kind of secret string. The backend Prosody module
does not verify the signature, we're only interested in passing data through Jitsi to the
Prosody module piggybacking on the token auth mechanism.

## Configuration

Add the auth to your Jitsi Meet Prosody virtualhost section:

```lua
VirtualHost "example.com"
    authentication = "matrix_user_verification"

    -- Must be set for the auth token to be passed through
    -- Must match what is being set as `iss` in the JWT
    app_id = "issuer"

    -- Base URL to the matrix user verification service (without ending slash)
    uvs_base_url = "https://uvs.example.com"
```

## License

Apache 2.0
