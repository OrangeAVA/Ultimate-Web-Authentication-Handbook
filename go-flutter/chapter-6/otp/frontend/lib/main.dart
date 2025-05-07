import 'dart:async';
import 'dart:convert';
import 'package:otp/otp.dart';

import 'package:flutter/material.dart';
import 'package:timer_count_down/timer_controller.dart';
import 'package:timer_count_down/timer_count_down.dart';
import 'package:http/http.dart' as http;
import 'package:provider/provider.dart';

class KeyData extends ChangeNotifier {
  Map data = {
    "type": "totp",
    "period": "30",
    "counter": "0",
    "secret": "ABCDEFGHIJKLMNOP",
    "algorithm": "SHA1",
    "digits": "6",
  };
  setData(Map d) {
    data = d;
    notifyListeners();
  }
}

void main() {
  runApp(const OTPApp());
}

class OTPApp extends StatelessWidget {
  const OTPApp({super.key});

  // This widget is the root of your application.
  @override
  Widget build(BuildContext context) {
    return ChangeNotifierProvider(
      create: (context) => KeyData(),
      child: const MaterialApp(
        title: 'OTP Demo',
        home: OTPPage(title: 'OTP Demo Page'),
      ),
    );
  }
}

const padding = Padding(padding: EdgeInsets.all(10));

class OTPPage extends StatefulWidget {
  const OTPPage({super.key, required this.title});

  final String title;

  @override
  State<OTPPage> createState() => _OTPPageState();
}

class _OTPPageState extends State<OTPPage> {
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(widget.title),
      ),
      body: Table(
        children: [
          TableRow(
            children: <Widget>[
              const RegistrationView(),
              padding,
              const ValidationView(),
              padding,
              AuthenticatorView(
                secret: Provider.of<KeyData>(context).data["secret"],
                type: Provider.of<KeyData>(context).data["type"],
              ),
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

class _RegistrationViewState extends State<RegistrationView> {
  final TextEditingController userCtrl = TextEditingController();

  Future<Map> getOtpData(String username, bool isTotp) {
    var queryParameters = {
      "username": username,
    };
    if (!isTotp) {
      queryParameters["type"] = "hotp";
    }
    return http
        .get(Uri(
            scheme: "https",
            path: "/register",
            queryParameters: queryParameters))
        .then((res) {
      if (res.statusCode == 200) {
        return jsonDecode(res.body);
      } else {
        throw Exception("${res.statusCode} ${res.body}");
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    final keyinfo = Provider.of<KeyData>(context).data;
    final image = keyinfo["image"];
    var qrimage = (image != null && image != "")
        ? Image.memory(base64Decode(image))
        : Image.asset("images/no-qrcode.png");

    final periodOrCounter = (keyinfo["type"] == "totp")
        ? TableRow(children: [
            const Text("Period"),
            Text(keyinfo["period"]!),
          ])
        : const TableRow(children: [
            Text("Counter"),
            Text("0"),
          ]);

    return Column(children: [
      const Text("Registration"),
      TextField(
        decoration: const InputDecoration(
          border: UnderlineInputBorder(),
          hintText: 'Enter your username ',
        ),
        controller: userCtrl,
      ),
      padding,
      qrimage,
      padding,
      Text(keyinfo["secret"]!),
      Table(
        border: TableBorder.all(),
        children: [
          TableRow(children: [
            const Text("Type"),
            Text(keyinfo["type"]!),
          ]),
          TableRow(children: [
            const Text("Algorithm"),
            Text(keyinfo["algorithm"]!),
          ]),
          TableRow(children: [
            const Text("Digits"),
            Text(keyinfo["digits"]!),
          ]),
          periodOrCounter,
        ],
      ),
      padding,
      ValueListenableBuilder(
        valueListenable: userCtrl,
        builder: (context, uname, child) {
          return ElevatedButton(
            onPressed: uname.text.isEmpty
                ? null
                : () {
                    getOtpData(uname.text, true).then((kinfo) {
                      Provider.of<KeyData>(context).setData(kinfo);
                      setState(() {});
                    });
                  },
            child: const Text("Generate New TOTP Key"),
          );
        },
      ),
      padding,
      ValueListenableBuilder(
        valueListenable: userCtrl,
        builder: (context, uname, child) {
          return ElevatedButton(
            onPressed: uname.text.isEmpty
                ? null
                : () {
                    getOtpData(uname.text, false).then((kinfo) {
                      Provider.of<KeyData>(context).setData(kinfo);
                      setState(() {});
                    });
                  },
            child: const Text("Generate New HOTP Key"),
          );
        },
      ),
      padding,
    ]);
  }
}

class ValidationView extends StatefulWidget {
  const ValidationView({super.key});
  @override
  State<ValidationView> createState() => _ValidationViewState();
}

class _ValidationViewState extends State<ValidationView> {
  final ValueNotifier<String> authRes = ValueNotifier<String>("");
  final TextEditingController vuserCtrl = TextEditingController();
  final TextEditingController otpCtrl = TextEditingController();

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        const Text("Validation"),
        TextField(
          decoration: const InputDecoration(
            border: UnderlineInputBorder(),
            hintText: 'Enter your username',
          ),
          controller: vuserCtrl,
        ),
        ValueListenableBuilder(
          valueListenable: vuserCtrl,
          builder: (context, value, child) {
            return TextField(
              decoration: const InputDecoration(
                border: UnderlineInputBorder(),
                hintText: 'Enter your OTP',
              ),
              controller: otpCtrl,
              enabled: vuserCtrl.text.isNotEmpty,
            );
          },
        ),
        padding,
        ValueListenableBuilder(
          valueListenable: otpCtrl,
          builder: (context, value, child) {
            return ElevatedButton(
              onPressed: value.text.isEmpty
                  ? null
                  : () {
                      http
                          .get(
                        Uri(
                          scheme: "https",
                          path: "/validate",
                          queryParameters: {
                            "username": vuserCtrl.text,
                            "otp": otpCtrl.text,
                          },
                        ),
                      )
                          .then(
                        (res) {
                          authRes.value = (res.statusCode == 200)
                              ? "Successfully validated"
                              : (res.statusCode == 401)
                                  ? "Validation failed"
                                  : "";
                        },
                      );
                    },
              child: const Text("Validate the OTP"),
            );
          },
        ),
        ValueListenableBuilder(
          valueListenable: authRes,
          builder: (context, value, child) {
            return Text(authRes.value);
          },
        ),
      ],
    );
  }
}

class AuthenticatorView extends StatefulWidget {
  const AuthenticatorView({
    super.key,
    required this.secret,
    required this.type,
    this.period = 30,
    this.counter = 1,
  });
  final String secret;
  final String type;
  final int counter;
  final int period;

  @override
  State<AuthenticatorView> createState() => _AuthenticatorViewState();
}

class _AuthenticatorViewState extends State<AuthenticatorView> {
  late int counter;
  late CountdownController remTimeCtrl;
  @override
  void initState() {
    super.initState();
    remTimeCtrl = CountdownController(autoStart: true);
    final period = widget.period * 1000;
    counter = (widget.type == "hotp")
        ? widget.counter
        : DateTime.now().millisecondsSinceEpoch ~/ period;
  }

  @override
  void dispose() {
    super.dispose();
  }

  @override
  void didUpdateWidget(covariant AuthenticatorView oldWidget) {
    if (oldWidget.type != widget.type) {
      final period = widget.period * 1000;
      counter = (widget.type == "hotp")
          ? widget.counter
          : DateTime.now().millisecondsSinceEpoch ~/ period;
    }
    super.didUpdateWidget(oldWidget);
  }

  @override
  Widget build(BuildContext context) {
    const padding = Padding(padding: EdgeInsets.all(10));
    final otp = widget.type == "hotp"
        ? OTP.generateHOTPCodeString(widget.secret, counter, isGoogle: true)
        : OTP.generateTOTPCodeString(
            widget.secret,
            DateTime.now().millisecondsSinceEpoch,
            algorithm: Algorithm.SHA1,
            isGoogle: true,
          );
    final trigger = widget.type == "hotp"
        ? ElevatedButton(
            onPressed: () {
              setState(() {
                counter++;
              });
            },
            child: const Text("Compute OTP"),
          )
        : Countdown(
            seconds: OTP.remainingSeconds(),
            build: (BuildContext context, double time) {
              return Text(time.toString());
            },
            onFinished: () => setState(() {
              counter++;
              remTimeCtrl.restart();
            }),
            controller: remTimeCtrl,
          );
    return Column(
      children: [
        const Text("Authenticator View"),
        padding,
        Text("Counter: $counter"),
        padding,
        Text("OTP: $otp"),
        trigger,
      ],
    );
  }
}
