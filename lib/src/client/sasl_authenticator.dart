import 'dart:typed_data';

import '../../sasl_scram.dart';
import 'auth.dart';

enum SaslMessageType {
  AuthenticationSASL,
  AuthenticationSASLContinue,
  AuthenticationSASLFinal,
}

abstract class SaslMechanism {
  String get name;

  SaslStep initialize();
}

abstract class SaslStep {
  Uint8List bytesToSendToServer;
  bool isComplete = false;

  SaslStep(this.bytesToSendToServer, {this.isComplete = false});

  SaslStep transition(List<int> bytesReceivedFromServer);
}

/// Structure for SASL Authenticator
abstract class SaslAuthenticator extends Authenticator {
  static const int DefaultNonceLength = 24;

  SaslMechanism mechanism;
  late SaslStep currentStep;

  SaslAuthenticator(this.mechanism) : super();

  @override
  Uint8List? handleMessage(SaslMessageType msgType, Uint8List bytesReceivedFromServer) {
    switch (msgType) {
      case SaslMessageType.AuthenticationSASL:
        currentStep = mechanism.initialize();
        break;
      case SaslMessageType.AuthenticationSASLContinue:
        currentStep = currentStep.transition(bytesReceivedFromServer);
        break;
      case SaslMessageType.AuthenticationSASLFinal:
        currentStep = currentStep.transition(bytesReceivedFromServer);
        return null;
      default:
        throw SaslScramException('Unsupported authentication type $msgType.');
    }
    return currentStep.bytesToSendToServer;
  }
}
