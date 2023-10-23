import 'dart:async';
import 'package:flutter/material.dart';
import 'package:url_launcher/url_launcher.dart';
import 'package:provider/provider.dart';
import 'dart:convert';
import 'dart:math';
import 'package:http/http.dart' as http;
import 'package:oauth2/oauth2.dart' as oauth2;

void main() {
  runApp(Provider(
    create: (context) => http.Client(),
    child: const IDPApp(),
  ));
}

class IDPApp extends StatelessWidget {
  const IDPApp({super.key});

  // This widget is the root of your application.
  @override
  Widget build(BuildContext context) {
    return const MaterialApp(
      title: "IDP Home Page",
      home: IDPHomePage(),
    );
  }
}

class IDPHomePage extends StatefulWidget {
  const IDPHomePage({super.key});

  @override
  State<IDPHomePage> createState() => _IDPHomePageState();
}

class _IDPHomePageState extends State<IDPHomePage> {
  static final Random _random = Random.secure();
  late TextEditingController dlgCtrl;
  late TextEditingController bodyCtrl;
  oauth2.Client? oauth2Client;

  @override
  void initState() {
    super.initState();
    dlgCtrl = TextEditingController();
    bodyCtrl = TextEditingController();
    bodyCtrl.text = "No token info found";
  }

  @override
  void dispose() {
    dlgCtrl.dispose();
    bodyCtrl.dispose();
    super.dispose();
  }

  Future<oauth2.Client?> getOAuthClient(BuildContext context) {
    final grant = oauth2.AuthorizationCodeGrant(
      "222222",
      Uri.parse("https://idp.local:8443/oauth/authorize"),
      Uri.parse("https://idp.local:8443/oauth/token"),
      httpClient: Provider.of<http.Client>(context, listen: false),
      codeVerifier:
          base64Url.encode(List<int>.generate(32, (i) => _random.nextInt(256))),
    );

    final authURI =
        grant.getAuthorizationUrl(Uri.parse("https://mysrv.local:8444/"));
    // ignore: avoid_print
    print(authURI);
    return launchUrl(
      authURI,
    ).then((ok) {
      return showDialog<String>(
        context: context,
        builder: (context) {
          return AlertDialog(
              title: const Text("Please enter the code"),
              content: TextField(
                autofocus: true,
                controller: dlgCtrl,
              ),
              actions: [
                TextButton(
                  onPressed: () => Navigator.of(context).pop(dlgCtrl.text),
                  child: const Text("SUBMIT"),
                )
              ]);
        },
      );
    }).then((code) {
      return ((code == null) || (code == ""))
          ? Future.value(null)
          : grant.handleAuthorizationCode(code);
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text("OAuth IDP Demo"),
        actions: [
          IconButton(
            onPressed:
                (oauth2Client != null) && (oauth2Client!.credentials.isExpired)
                    ? () {
                        oauth2Client!.refreshCredentials().then((_) {
                          bodyCtrl.text +=
                              "${oauth2Client!.credentials.toJson()}\n";
                          setState(() {});
                        }).then((_) {
                          final wait = oauth2Client!.credentials.expiration!
                                  .difference(DateTime.now()) +
                              const Duration(seconds: 1);
                          Future.delayed(wait, () {
                            setState(() {});
                          });
                        });
                      }
                    : null,
            icon: const Icon(Icons.refresh),
          ),
          IconButton(
            onPressed: () {
              getOAuthClient(context).then((client) {
                oauth2Client = client;
                return oauth2Client;
              }).then((client) {
                return client != null
                    ? client.get(Uri.parse("https://mysrv.local:8444/resource"))
                    : Future.value(null);
              }).then((res) {
                bodyCtrl.text =
                    "${res?.body ?? "No token info found\n"}${oauth2Client!.credentials.toJson()}\n";
                final wait = oauth2Client!.credentials.expiration!
                        .difference(DateTime.now()) +
                    const Duration(seconds: 1);
                Future.delayed(wait, () {
                  setState(() {});
                });
              });
            },
            icon: const Icon(Icons.lock),
          ),
        ],
      ),
      body: TextField(
        controller: bodyCtrl,
        keyboardType: TextInputType.multiline,
        maxLines: null,
        canRequestFocus: false,
        autofocus: false,
      ),
    );
  }
}
