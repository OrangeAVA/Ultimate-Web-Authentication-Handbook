import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:http/http.dart' as http;

void main() {
  runApp(MultiProvider(
    providers: [
      Provider(create: (context) => http.Client()),
    ],
    child: const FinanceApp(),
  ));
}

class FinanceApp extends StatelessWidget {
  const FinanceApp({super.key});

  // This widget is the root of your application.
  @override
  Widget build(BuildContext context) {
    return const MaterialApp(
      title: 'Finance Portal',
      home: FinanceHomePage(),
    );
  }
}

class FinanceHomePage extends StatelessWidget {
  const FinanceHomePage({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Finance App')),
      body: FutureBuilder<String>(
        future: Provider.of<http.Client>(context)
            .get(Uri(scheme: "https", path: "/data"))
            .then((res) {
          if (res.statusCode == 200) {
            return res.body;
          } else {
            throw Exception("No data found.");
          }
        }),
        builder: (BuildContext context, AsyncSnapshot<String> snapshot) {
          if (snapshot.hasData) {
            var data = jsonDecode(snapshot.data!);
            List<TableRow> rows = [];
            rows.add(const TableRow(
                children: [Text("User"), Text("Monthly Salary in USD")]));
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
