import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:provider/provider.dart';
import 'package:xml/xml.dart';
import 'package:url_launcher/url_launcher.dart';
import 'dart:html';

class CookieRead extends ChangeNotifier {
  String? uid;
  bool sploaded = false;

  readCookies() {
    uid = null;
    sploaded = false;
    if (document.cookie != null) {
      var cookies = document.cookie!.split(';');
      for (var cookie in cookies) {
        final splitted = cookie.split('=');
        if (splitted[0].trim() == "uid") {
          uid = splitted[1].trim();
        }
        if (splitted[0].trim() == "sploaded") {
          sploaded = (splitted[1].toLowerCase() == "true");
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

class SPRead extends ChangeNotifier {
  refresh() {
    notifyListeners();
  }
}

class SessionRead extends ChangeNotifier {
  refresh() {
    notifyListeners();
  }
}

void main() {
  runApp(MultiProvider(
    providers: [
      ChangeNotifierProvider<SPRead>(create: (context) => SPRead()),
      ChangeNotifierProvider<SessionRead>(create: (context) => SessionRead()),
      ChangeNotifierProvider<CookieRead>(create: (context) => CookieRead()),
      Provider(create: (context) => http.Client()),
    ],
    child: const IDPApp(),
  ));
}

class IDPApp extends StatelessWidget {
  const IDPApp({super.key});

  // This widget is the root of your application.
  @override
  Widget build(BuildContext context) {
    return const MaterialApp(
      title: 'HOWA Identity Provider',
      home: IDPHomePage(title: 'HOWA Identity Provider'),
    );
  }
}

class IDPHomePage extends StatelessWidget {
  const IDPHomePage({super.key, required this.title});
  final String title;
  Future<List<String>> getData(BuildContext context, String rectype) async {
    var uri = Uri(scheme: "https", path: "/idp/$rectype/");
    var clnt = Provider.of<http.Client>(context);
    var retval = <String>[];
    var res = await clnt.get(uri);
    if (res.statusCode == 200) {
      var m = jsonDecode(res.body);
      List<Future> futures = [];
      m.forEach((k, v) {
        for (var n in v.toList()) {
          n = Uri.encodeFull("$n");
          var uri = Uri(scheme: "https", path: "/idp/$rectype/$n");
          futures.add(clnt.get(uri));
        }
      });
      var ress = await Future.wait(futures);
      for (res in ress) {
        retval.add(res.body);
      }
    }
    return retval;
  }

  TableRow buildTableRow(BuildContext context, String rectype, String? row) {
    switch (rectype) {
      case "users":
        var json = (row != null) ? jsonDecode(row) : null;
        return TableRow(
          children: [
            Text(row == null ? "Name" : json["name"]),
            Text(row == null ? "Email" : json["email"]),
            Text(row == null ? "Groups" : json["groups"].toString()),
          ],
        );
      case "shortcuts":
        var json = (row != null) ? jsonDecode(row) : null;
        return TableRow(
          children: [
            (row == null)
                ? const Text("Name")
                : Consumer<CookieRead>(
                    builder: (context, cr, child) {
                      var sc = json["name"];
                      return (cr.uid != null)
                          ? InkWell(
                              child: Text(sc),
                              onTap: () async {
                                await launchUrl(
                                  Uri(scheme: "https", path: "/idp/login/$sc"),
                                  webOnlyWindowName: "_blank",
                                );
                              },
                            )
                          : Text(sc);
                    },
                  ),
            Text(row == null ? "SP" : json["service_provider"]),
          ],
        );
      case "services":
        if (row == null) {
          return const TableRow(
            children: [Text("Services")],
          );
        } else {
          var doc = XmlDocument.parse(row);
          var entityid = doc.children[0].getAttribute("entityID");
          return TableRow(
            children: [Text(entityid == null ? "NA" : entityid)],
          );
        }
      case "sessions":
        var json = (row != null) ? jsonDecode(row) : null;
        return TableRow(
          children: [
            Text(row == null ? "ID" : json["ID"]),
            Text(row == null ? "CreateTime" : json["CreateTime"]),
            Text(row == null ? "ExpireTime" : json["ExpireTime"]),
            Text(row == null ? "UserName" : json["UserName"]),
            Text(row == null ? "Groups" : json["Groups"].toString()),
          ],
        );
      default:
        return const TableRow(children: []);
    }
  }

  FutureBuilder<List<String>> buildTable(BuildContext context, String rectype) {
    return FutureBuilder<List<String>>(
        future: getData(context, rectype),
        builder: (BuildContext context, AsyncSnapshot<List<String>> snapshot) {
          if (snapshot.hasData) {
            List<String> strs = snapshot.data!;
            List<TableRow> rows = [];
            rows.add(buildTableRow(context, rectype, null));
            for (var s in strs) {
              rows.add(buildTableRow(context, rectype, s));
            }
            return Table(
              children: rows,
              border: TableBorder.all(),
            );
          } else if (snapshot.hasError) {
            return const Text("Unable to read data");
          } else {
            return const Text("Reading data...");
          }
        });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Identity Provider'),
        actions: [
          Consumer<CookieRead>(
            builder: (context, cr, child) {
              if (cr.uid == null) {
                return IconButton(
                  onPressed: cr.sploaded
                      ? () {
                          launchUrl(
                            Uri(scheme: "https", path: "/auth/"),
                            webOnlyWindowName: "_self",
                          ).then((_) =>
                              Provider.of<CookieRead>(context).refresh());
                        }
                      : null,
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
      body: GridView.count(
          primary: false,
          padding: const EdgeInsets.all(20),
          crossAxisSpacing: 10,
          mainAxisSpacing: 10,
          crossAxisCount: 2,
          childAspectRatio: 2,
          children: [
            Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              const Text(
                "Users",
                style: TextStyle(fontSize: 24),
              ),
              buildTable(context, "users"),
            ]),
            Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              const Text(
                "Services",
                style: TextStyle(fontSize: 24),
              ),
              ElevatedButton(
                onPressed: () {
                  var uri = Uri(scheme: "https", path: "/addsps");
                  Provider.of<http.Client>(context).get(uri).then((res) {
                    if (res.statusCode == 200) {
                      Provider.of<SPRead>(context).refresh();
                      Provider.of<CookieRead>(context).refresh();
                    }
                  });
                },
                child: const Text("Load the SPs"),
              ),
              Consumer<SPRead>(
                builder: (context, value, child) =>
                    buildTable(context, "services"),
              ),
            ]),
            Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              const Text(
                "Shortcuts",
                style: TextStyle(fontSize: 24),
              ),
              Consumer<SPRead>(
                builder: (context, value, child) =>
                    buildTable(context, "shortcuts"),
              )
            ]),
            Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              const Text(
                "Sessions",
                style: TextStyle(fontSize: 24),
              ),
              ElevatedButton(
                onPressed: () {
                  Provider.of<SessionRead>(context).refresh();
                },
                child: const Text("Refresh Sessions"),
              ),
              Consumer<SessionRead>(
                builder: (context, value, child) =>
                    buildTable(context, "sessions"),
              ),
            ]),
          ]),
    );
  }
}
