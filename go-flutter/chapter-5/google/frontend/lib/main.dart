import 'package:flutter/material.dart';
import 'package:url_launcher/url_launcher.dart';
import 'dart:convert';
import 'package:http/http.dart' as http;

void main() {
  runApp(const OIDCDemoApp());
}

class OIDCDemoApp extends StatelessWidget {
  const OIDCDemoApp({super.key});

  // This widget is the root of your application.
  @override
  Widget build(BuildContext context) {
    return const MaterialApp(
      title: "OIDC Demo Home Page",
      home: OIDCAppHomePage(),
    );
  }
}

class OIDCAppHomePage extends StatefulWidget {
  const OIDCAppHomePage({super.key});

  @override
  State<OIDCAppHomePage> createState() => _OIDCAppHomePageState();
}

class _OIDCAppHomePageState extends State<OIDCAppHomePage> {
  static const padding = EdgeInsets.all(10);
  late Future<String> userinfo;
  late Future<String> idtoken;

  @override
  void initState() {
    super.initState();
    userinfo = getInfo(Uri(scheme: "http", path: "/userinfo"));
    idtoken = getInfo(Uri(scheme: "http", path: "/idtoken"));
  }

  @override
  void dispose() {
    super.dispose();
  }

  Future<String> getInfo(Uri uri) async {
    var res = await http.get(uri);
    if (res.statusCode == 200) {
      return res.body;
    } else {
      throw Exception("${res.statusCode} ${res.body}");
    }
  }

  Widget getLoginButton(BuildContext context) {
    return FutureBuilder(
      future: userinfo,
      builder: (BuildContext ctx, AsyncSnapshot<String> sn) {
        final path = sn.hasData ? "/oauth/logout" : "/oauth/login";
        final btnTxt = sn.hasData ? "Logout" : "Login";
        return TextButton(
          onPressed: () => launchUrl(Uri(scheme: "http", path: path),
              webOnlyWindowName: "_self"),
          child: Text(btnTxt, style: const TextStyle(color: Colors.black)),
        );
      },
    );
  }

  Widget getUserInfo(BuildContext context) {
    return FutureBuilder(
      future: userinfo,
      builder: (BuildContext ctx, AsyncSnapshot<String> sn) {
        if (sn.hasData) {
          List<TableRow> trs = [];
          Map<String, dynamic> m = jsonDecode(sn.data!);
          m.forEach((k, v) {
            trs.add(TableRow(children: [
              Padding(
                padding: padding,
                child: Text(k),
              ),
              Padding(
                padding: padding,
                child: Text(v.toString()),
              ),
            ]));
          });
          return Table(
            defaultColumnWidth: const IntrinsicColumnWidth(),
            children: trs,
            border: TableBorder.all(),
          );
        } else if (sn.hasError) {
          return Text(sn.error.toString());
        } else {
          return const Text("Reading data...");
        }
      },
    );
  }

  Widget getIDToken(BuildContext context) {
    return FutureBuilder(
      future: idtoken,
      builder: (BuildContext ctx, AsyncSnapshot<String> sn) {
        if (sn.hasData) {
          Map<String, dynamic> m = jsonDecode(sn.data!);
          const encoder = JsonEncoder.withIndent("    ");
          final headerPretty = encoder.convert(m["Header"]!);
          final claimsPretty = encoder.convert(m["Claims"]!);
          final signature = m["Signature"]!;
          final valid = m["Valid"]!;

          const padding = EdgeInsets.all(10);
          return Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Padding(
                padding: padding,
                child: Text("Header"),
              ),
              Text(headerPretty),
              const Padding(
                padding: padding,
                child: Text("Claims"),
              ),
              Text(claimsPretty),
              const Text("Signature"),
              Text(signature),
              Text("Valid: ${valid.toString()}"),
            ],
          );
        } else if (sn.hasError) {
          return Text(sn.error.toString());
        } else {
          return const Text("Reading data...");
        }
      },
    );
  }

  @override
  Widget build(BuildContext context) {
    const padding = EdgeInsets.all(10);
    return Scaffold(
      appBar: AppBar(
        title: const Text("OIDC Demo"),
        actions: [
          Padding(
            padding: padding,
            child: getLoginButton(context),
          ),
        ],
      ),
      body: SingleChildScrollView(
        child: Table(
          children: [
            const TableRow(
              children: [
                Padding(
                  padding: padding,
                  child: Text("UserInfo"),
                ),
                Padding(
                  padding: padding,
                  child: Text("ID Token"),
                ),
              ],
            ),
            TableRow(
              children: [
                Padding(
                  padding: padding,
                  child: getUserInfo(context),
                ),
                Padding(
                  padding: padding,
                  child: getIDToken(context),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}
