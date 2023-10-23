import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:provider/provider.dart';
import 'package:url_launcher/url_launcher.dart';

void main() {
  runApp(Provider(
    create: (context) => http.Client(),
    child: const GHApp(),
  ));
}

class GHApp extends StatelessWidget {
  const GHApp({super.key});

  // This widget is the root of your application.
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
        title: "GitHub User Profile",
        home: FutureBuilder(
          future: Provider.of<http.Client>(context)
              .get(Uri(scheme: "https", path: "/resource"))
              .then((res) {
            if (res.statusCode == 200) return res.body;
            throw "Failed to authenticate";
          }),
          builder: (BuildContext ctx, AsyncSnapshot snapshot) {
            if (snapshot.hasData) {
              var m = jsonDecode(snapshot.data!);
              return Scaffold(
                  appBar: AppBar(
                    title: const Text("User Information"),
                    actions: [
                      ElevatedButton(
                        onPressed: () async {
                          await launchUrl(
                            Uri(scheme: "https", path: "/oauth/logout"),
                            webOnlyWindowName: "_self",
                          );
                        },
                        child: const Text("Logout"),
                      )
                    ],
                  ),
                  body: Column(
                    children: [
                      Text(m["login"]),
                      Image.network(m["avatar_url"]),
                      Text(m["name"]),
                      Text(m["email"]),
                    ],
                  ));
            } else if (snapshot.hasError) {
              return Scaffold(
                appBar: AppBar(
                  title: const Text("User Information"),
                  actions: [
                    ElevatedButton(
                      onPressed: () async {
                        await launchUrl(
                          Uri(scheme: "https", path: "/oauth/login"),
                          webOnlyWindowName: "_self",
                        );
                      },
                      child: const Text("Login"),
                    )
                  ],
                ),
                body: const Text("Unable to read data. Login."),
              );
            } else {
              return const Text("Reading data...");
            }
          },
        ));
  }
}
