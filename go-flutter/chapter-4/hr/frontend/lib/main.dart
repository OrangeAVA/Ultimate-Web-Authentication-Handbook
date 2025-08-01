import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:http/http.dart' as http;
import 'package:url_launcher/url_launcher.dart';
import 'dart:html';

class CookieRead extends ChangeNotifier {
  String? uid;
  readCookies() {
    uid = null;
    if (document.cookie != null) {
      var cookies = document.cookie!.split(';');
      for (var cookie in cookies) {
        final splitted = cookie.split('=');
        if (splitted[0].trim() == "uid") {
          uid = splitted[1].trim();
        }
      }
    }
  }

  CookieRead() {
    readCookies();
  }
  refresh() {
    readCookies();
    notifyListeners();
  }
}

void main() {
  runApp(MultiProvider(
    providers: [
      ChangeNotifierProvider<CookieRead>(create: (context) => CookieRead()),
      Provider(create: (context) => http.Client()),
    ],
    child: const HRApp(),
  ));
}

class HRApp extends StatelessWidget {
  const HRApp({super.key});

  // This widget is the root of your application.
  @override
  Widget build(BuildContext context) {
    return const MaterialApp(
      title: 'HR Portal',
      home: HRHomePage(),
    );
  }
}

class HRHomePage extends StatelessWidget {
  const HRHomePage({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('HR App'),
        actions: [
          Consumer<CookieRead>(
            builder: (context, cr, child) {
              if (cr.uid == null) {
                return IconButton(
                  onPressed: () {
                    launchUrl(
                      Uri(scheme: "https", path: "/auth/"),
                      webOnlyWindowName: "_self",
                    ).then((_) => Provider.of<CookieRead>(context).refresh());
                  },
                  icon: const Icon(Icons.lock),
                  tooltip: "Login",
                );
              } else {
                return Row(
                  children: <Widget>[
                    Text(cr.uid!),
                    IconButton(
                      onPressed: () {
                        launchUrl(
                          Uri(scheme: "https", path: "/auth/logout"),
                          webOnlyWindowName: "_self",
                        ).then(
                            (_) => Provider.of<CookieRead>(context).refresh());
                      },
                      icon: const Icon(Icons.lock_open),
                      tooltip: "Logout",
                    ),
                  ],
                );
              }
            },
          )
        ],
      ),
      body: FutureBuilder<String>(
        future: Provider.of<http.Client>(context)
            .get(Uri(scheme: "https", path: "/data"))
            .then((res) {
          if (res.statusCode == 200) {
            return res.body;
          } else {
            throw Exception("Cannot access data.");
          }
        }),
        builder: (BuildContext context, AsyncSnapshot<String> snapshot) {
          if (snapshot.hasData) {
            var data = jsonDecode(snapshot.data!);
            List<TableRow> rows = [];
            rows.add(const TableRow(
                children: [Text("User"), Text("Pending Leaves")]));
            data.forEach((k, v) {
              rows.add(TableRow(children: [Text(k), Text(v.toString())]));
            });
            return Padding(
                padding: const EdgeInsets.all(20.0),
                child: Table(
                  children: rows,
                  border: TableBorder.all(),
                ));
          } else if (snapshot.hasError) {
            String err = snapshot.error!.toString();
            return Text(err);
          } else {
            return const Text("Reading data...");
          }
        },
      ),
    );
  }
}
