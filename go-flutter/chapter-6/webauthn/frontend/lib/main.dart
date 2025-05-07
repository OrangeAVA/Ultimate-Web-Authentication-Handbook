import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
// ignore: avoid_web_libraries_in_flutter
import 'dart:html';

import 'package:uuid/uuid.dart';

void main() {
  runApp(const WebAuthnApp());
}

class WebAuthnApp extends StatelessWidget {
  const WebAuthnApp({super.key});

  // This widget is the root of your application.
  @override
  Widget build(BuildContext context) {
    return const MaterialApp(
      title: 'WebAuthn Demo',
      home: WebauthnPage(title: 'WebAuthn Demo Page'),
    );
  }
}

const padding = Padding(padding: EdgeInsets.all(10));

class WebauthnPage extends StatelessWidget {
  const WebauthnPage({super.key, required this.title});

  final String title;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(title),
      ),
      body: Table(
        children: const [
          TableRow(
            children: <Widget>[
              padding,
              RegistrationView(),
              padding,
              AuthenticationView(),
              padding,
            ],
          ),
        ],
      ),
    );
  }
}

class RegistrationView extends StatefulWidget {
  const RegistrationView({super.key});

  @override
  State<RegistrationView> createState() => _RegistrationViewState();
}

Future<Map> httpPost(String path, Map<String, dynamic> params, Object? body) {
  var js = "";

  if (body != null) {
    js = jsonEncode(body);
  }
  return http
      .post(
    Uri(scheme: "https", path: path, queryParameters: params),
    headers: {"Content-Type": "application/json"},
    body: js,
  )
      .then((res) {
    if (res.statusCode == 200) {
      return jsonDecode(res.body);
    } else {
      throw Exception("${res.statusCode} ${res.body}");
    }
  });
}

ByteBuffer str2buffer(String s) {
  var r = 4 - s.length.remainder(4);
  while (r > 0) {
    s += "=";
    r--;
  }
  return base64Url.decode(s).buffer;
}

String buffer2str(ByteBuffer buf) {
  return base64UrlEncode(buf.asUint8List());
}

class _RegistrationViewState extends State<RegistrationView> {
  final TextEditingController userCtrl = TextEditingController();
  String regStatus = "";
  @override
  Widget build(BuildContext context) {
    return Column(
      children: <Widget>[
        const Text("Registration View"),
        padding,
        TextField(
          decoration: const InputDecoration(
            border: UnderlineInputBorder(),
            hintText: 'Username',
          ),
          controller: userCtrl,
        ),
        padding,
        ValueListenableBuilder(
          valueListenable: userCtrl,
          builder: (context, uctrl, child) {
            return ElevatedButton(
              onPressed: uctrl.text.isEmpty
                  ? null
                  : () async {
                      try {
                        final state = const Uuid().v4();
                        final res = await httpPost(
                            "/webauthn/register/begin",
                            {
                              "username": userCtrl.text,
                              "state": state,
                            },
                            null);
                        final publicKey = res["publicKey"];
                        if (publicKey == null ||
                            !publicKey.containsKey("challenge")) {
                          return;
                        }

                        final challenge = publicKey["challenge"];
                        res["publicKey"]["challenge"] = str2buffer(challenge);
                        final uid = publicKey["user"]["id"];
                        res["publicKey"]["user"]["id"] = str2buffer(uid);
                        final cred =
                            await window.navigator.credentials?.create(res);

                        if (cred == null) {
                          throw Exception("Failed to acquire credentials.");
                        } else {
                          var obj = {
                            "id": cred.id,
                            "rawId": buffer2str(cred.rawId),
                            "type": 'public-key',
                          };

                          obj["response"] = {
                            "attestationObject":
                                buffer2str(cred.response.attestationObject),
                            "clientDataJson":
                                buffer2str(cred.response.clientDataJson),
                          };

                          final res1 = await httpPost(
                              "/webauthn/register/finish",
                              {
                                "username": userCtrl.text,
                                "state": state,
                              },
                              obj);
                          setState(() {
                            regStatus = res1["message"];
                          });
                        }
                      } catch (e) {
                        setState(() {
                          regStatus = e.toString();
                        });
                      }
                    },
              child: const Text("Register"),
            );
          },
        ),
        Text(regStatus),
      ],
    );
  }
}

class AuthenticationView extends StatefulWidget {
  const AuthenticationView({super.key});

  @override
  State<AuthenticationView> createState() => _AuthenticationViewState();
}

class _AuthenticationViewState extends State<AuthenticationView> {
  final TextEditingController userCtrl = TextEditingController();
  String authStatus = "";
  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        const Text("Authentication View"),
        padding,
        TextField(
          decoration: const InputDecoration(
            border: UnderlineInputBorder(),
            hintText: 'Username',
          ),
          controller: userCtrl,
        ),
        padding,
        ValueListenableBuilder(
          valueListenable: userCtrl,
          builder: (context, uctrl, child) {
            return ElevatedButton(
              onPressed: uctrl.text.isEmpty
                  ? null
                  : () async {
                      try {
                        final state = const Uuid().v4();
                        final res = await httpPost(
                            "/webauthn/login/begin",
                            {
                              "username": userCtrl.text,
                              "state": state,
                            },
                            null);
                        final publicKey = res["publicKey"];
                        if (publicKey == null ||
                            !publicKey.containsKey("challenge")) {
                          return;
                        }

                        final challenge = publicKey["challenge"];
                        res["publicKey"]["challenge"] = str2buffer(challenge);

                        final allowedcreds = publicKey["allowCredentials"];

                        for (int i = 0; i < allowedcreds.length; i++) {
                          final cid = allowedcreds[i]["id"];
                          res["publicKey"]["allowCredentials"][i]["id"] =
                              str2buffer(cid);
                        }

                        final cred =
                            await window.navigator.credentials?.get(res);

                        if (cred == null) {
                          throw Exception("Failed to acquire credentials.");
                        } else {
                          var obj = {
                            "id": cred.id,
                            "rawId": buffer2str(cred.rawId),
                            "type": 'public-key',
                          };

                          obj["response"] = {
                            "authenticatorData":
                                buffer2str(cred.response.authenticatorData),
                            "signature": buffer2str(cred.response.signature),
                            "clientDataJson":
                                buffer2str(cred.response.clientDataJson),
                          };

                          final res1 = await httpPost(
                              "/webauthn/login/finish",
                              {
                                "username": userCtrl.text,
                                "state": state,
                              },
                              obj);
                          setState(() {
                            authStatus = res1["message"];
                          });
                        }
                      } catch (e) {
                        setState(() {
                          authStatus = e.toString();
                        });
                      }
                    },
              child: const Text("Authenticate"),
            );
          },
        ),
        Text(authStatus),
      ],
    );
  }
}
