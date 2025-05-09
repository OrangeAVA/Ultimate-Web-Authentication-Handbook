import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:http/http.dart' as http;
import 'package:url_launcher/url_launcher.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  // This widget is the root of your application.
  @override
  Widget build(BuildContext context) {
    return const MaterialApp(
      title: 'OIDC with TOTP and WebAuthn',
      home: MyHomePage(title: 'OIDC with TOTP and WebAuthn'),
    );
  }
}

class MyHomePage extends StatefulWidget {
  const MyHomePage({super.key, required this.title});
  final String title;

  @override
  State<MyHomePage> createState() => _MyHomePageState();
}

class _MyHomePageState extends State<MyHomePage> {
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(widget.title),
        actions: [
          TextButton(
            onPressed: () async {
              await launchUrl(
                Uri(scheme: 'https', path: '/oauth/login'),
                webOnlyWindowName: "_self",
              );
            },
            child: const Text(
              "Login",
              style: TextStyle(color: Colors.black),
            ),
          ),
          TextButton(
            onPressed: () async {
              await launchUrl(
                Uri(scheme: 'https', path: '/oauth/logout'),
                webOnlyWindowName: "_self",
              );
            },
            child: const Text(
              "Logout",
              style: TextStyle(color: Colors.black),
            ),
          ),
        ],
      ),
      body: Center(
        child: FutureBuilder(
          future: http.get(Uri(scheme: 'https', path: '/resource')).then((res) {
            if (res.statusCode == 200) {
              return res.body;
            } else {
              throw Exception("${res.statusCode} ${res.body}");
            }
          }),
          builder: (BuildContext context, AsyncSnapshot sn) {
            if (sn.hasData) {
              return Text(sn.data!);
            } else if (sn.hasError) {
              return Text(sn.error!.toString());
            } else {
              return const Text("Getting the user info...");
            }
          },
        ),
      ),
    );
  }
}
