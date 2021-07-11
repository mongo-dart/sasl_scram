import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:crypto/crypto.dart';

import '../../../sasl_scram_exception.dart';
import '../../../utils/parsing.dart';
import '../../../utils/sasl.dart';
import '../../../utils/typed_data.dart';
import '../../auth.dart';
import '../../sasl_authenticator.dart';
import 'client_last.dart';

class ClientFirst extends SaslStep {
  final String clientFirstMessageBare;
  final UsernamePasswordCredential credential;
  final String rPrefix;
  final Hash hash;

  ClientFirst(Uint8List bytesToSendToServer, this.hash, this.credential, this.clientFirstMessageBare, this.rPrefix)
      : super(bytesToSendToServer);

  @override
  SaslStep transition(List<int> bytesReceivedFromServer) {
    final serverFirstMessage = utf8.decode(bytesReceivedFromServer);

    final Map<String, dynamic> decodedMessage = parsePayload(serverFirstMessage);

    final r = decodedMessage['r'] as String?;
    if (r == null || !r.startsWith(rPrefix)) {
      throw SaslScramException('Server sent an invalid nonce.');
    }

    final s = decodedMessage['s'];
    final i = int.parse(decodedMessage['i'].toString());

    final encodedHeader = base64.encode(utf8.encode(gs2Header));
    final channelBinding = 'c=$encodedHeader';
    final nonce = 'r=$r';
    final clientFinalMessageWithoutProof = '$channelBinding,$nonce';

    // final passwordDigest = md5DigestPassword(credential.username, credential.password);
    // TODO Mongo uses password digest, which isn't specified in the protocol (?)
    final passwordDigest = credential.password!;
    final salt = base64.decode(s.toString());

    final saltedPassword = hi(passwordDigest, salt, i, hash);
    final clientKey = computeHMAC(saltedPassword, 'Client Key', hash);
    final storedKey = h(clientKey, hash);
    final authMessage = '$clientFirstMessageBare,$serverFirstMessage,$clientFinalMessageWithoutProof';
    final clientSignature = computeHMAC(storedKey, authMessage, hash);
    final clientProof = xor(clientKey, clientSignature);
    final serverKey = computeHMAC(saltedPassword, 'Server Key', hash);
    final serverSignature = computeHMAC(serverKey, authMessage, hash);

    final base64clientProof = base64.encode(clientProof);
    final proof = 'p=$base64clientProof';
    final clientFinalMessage = '$clientFinalMessageWithoutProof,$proof';

    return ClientLast(coerceUint8List(utf8.encode(clientFinalMessage)), serverSignature);
  }

  static Uint8List computeHMAC(Uint8List data, String key, Hash hash) {
    final hmac = crypto.Hmac(hash, data);
    hmac.convert(utf8.encode(key));
    return Uint8List.fromList(hmac.convert(utf8.encode(key)).bytes);
  }

  static Uint8List h(Uint8List data, Hash hash) {
    return Uint8List.fromList(hash.convert(data).bytes);
  }

  /*static String md5DigestPassword(username, password) {
    return crypto.md5.convert(utf8.encode('$username:postgresql:$password')).toString();
  }*/

  static Uint8List xor(Uint8List a, Uint8List b) {
    final result = <int>[];

    if (a.length > b.length) {
      for (var i = 0; i < b.length; i++) {
        result.add(a[i] ^ b[i]);
      }
    } else {
      for (var i = 0; i < a.length; i++) {
        result.add(a[i] ^ b[i]);
      }
    }

    return Uint8List.fromList(result);
  }

  static Uint8List hi(String password, Uint8List salt, int iterations, Hash hash) {
    final digest = (List<int> msg) {
      final hmac = crypto.Hmac(hash, password.codeUnits);
      return Uint8List.fromList(hmac.convert(msg).bytes);
    };

    final newSalt = Uint8List.fromList(List.from(salt)..addAll([0, 0, 0, 1]));

    var ui = digest(newSalt);
    var u1 = ui;

    for (var i = 0; i < iterations - 1; i++) {
      u1 = digest(u1);
      ui = xor(ui, u1);
    }

    return ui;
  }
}
