# Diagram sources

## Widget creation

```
title Prosody auth of Jitsi - widget creation

Client->Jitsi: Query auth methods\n/.well-known/element/jitsi
Jitsi->Client: {"auth": "openidtoken-jwt"}
note over Client: Jitsi conference ID must be \nbase32 encoded room ID\n\nWidget URL should have extra parameter\n"auth=openidtoken-jwt"
Client->Synapse: Create widget
Synapse->Client: Widget created
```

## Widget load

```
title Prosody Matrix user verification auth - widget load

participant Client as Client

participant "Jitsi Widget" as Widget

Client->Widget: Load widget\n(widget URL needs to \ncontain auth type and room ID)

participant Jitsi/Prosody as Jitsi

Widget->Client: Ask for OpenID token\nMSC1960 (postmessage API)

Client->Synapse: Fetch OpenID token (C2S)

Synapse->Synapse: Generate OpenID token
Synapse->Client: Return OpenID token
Client->Widget: Pass in OpenID token\n(postmessage API)

Widget->Widget: Generate JWT containing\nOpenID token & RoomID

Widget->Jitsi: Attempt to join\npassing JWT as auth

Jitsi->Jitsi: Check that the Jitsi ID matches\nbase32 encoded room ID

participant User\nVerification\nService as UVS

Jitsi->UVS: OpenID token and room membership check\n(OpenID token, Room ID)
UVS->Synapse: Check OpenID token verifies (S2S)
Synapse->UVS: Verification response\nreturns Matrix ID
UVS->Synapse: Check user in the room\n(Synapse admin API)
Synapse->UVS: Verification response

UVS->Jitsi: Authentication response\n(returns also Matrix ID and room power levels)

Jitsi->Widget: Join the conference

Jitsi->Jitsi: Make participant conference\nowner if power levels match
```
