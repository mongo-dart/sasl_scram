# Sasl Scram for Dart

Implementation of the Salted Challenge Response Authentication Mechanism in Dart.

## Usage

A simple usage example:

```dart
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:sasl_scram/sasl_scram.dart';

void main() {
  final bytesReceivedFromServer = Uint8List(0); // No data needed when starting authentication

  final authenticator = ScramAuthenticator(
    'SCRAM-SHA-256', // Optionally choose hash method from a list provided by the server
    sha256,
    UsernamePasswordCredential(username: 'dart', password: 'dart'),
  );

  final bytesToSentToServer = authenticator.handleMessage(
    SaslMessageType.AuthenticationSASL, // Get type type from the server message
    bytesReceivedFromServer, // Append the remaining bytes
  );
  print(bytesToSentToServer); // Wrap these bytes with your message which goes back to the server
}
```

## Features and bugs

Please file feature requests and bugs at the [issue tracker][tracker].

[tracker]: https://github.com/mongo-dart/sasl_scram_dart/issues
