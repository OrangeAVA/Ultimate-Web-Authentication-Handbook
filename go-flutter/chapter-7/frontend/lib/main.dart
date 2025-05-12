import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:camera/camera.dart';

late List<CameraDescription> _cameras;
void main() async {
  _cameras = await availableCameras();
  runApp(const FaceRecApp());
}

class FaceRecApp extends StatelessWidget {
  const FaceRecApp({super.key});
  @override
  Widget build(BuildContext context) {
    return const MaterialApp(
      title: 'Face Recognition Demo',
      home: FaceRecPage(title: 'Face Recognition Demo Page'),
    );
  }
}

class FaceRecPage extends StatefulWidget {
  const FaceRecPage({super.key, required this.title});

  final String title;

  @override
  State<FaceRecPage> createState() => _FaceRecPageState();
}

class _FaceRecPageState extends State<FaceRecPage> {
  late CameraController cameraCtrl;

  @override
  void initState() {
    super.initState();
    cameraCtrl = CameraController(
      _cameras[0],
      ResolutionPreset.max,
      imageFormatGroup: ImageFormatGroup.jpeg,
    );
    cameraCtrl.initialize().then((_) {
      if (!mounted) {
        return;
      }
      setState(() {});
    }).catchError((Object e) {
      if (e is CameraException) {
        switch (e.code) {
          case 'CameraAccessDenied':
            // Handle access errors here.
            break;
          default:
            // Handle other errors here.
            break;
        }
      }
    });
  }

  @override
  void dispose() {
    cameraCtrl.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(widget.title),
      ),
      body: Center(
        child: Column(
          children: [
            SizedBox(
              height: 300,
              child: CameraPreview(cameraCtrl),
            ),
            FaceRecView(cameraCtrl: cameraCtrl),
          ],
        ),
      ),
    );
  }
}

class FaceRecView extends StatefulWidget {
  const FaceRecView({super.key, required this.cameraCtrl});

  final CameraController cameraCtrl;
  @override
  State<FaceRecView> createState() => _FaceRecViewState();
}

class _FaceRecViewState extends State<FaceRecView> {
  bool bImageCaptured1 = false;
  bool bImageCaptured2 = false;
  late Uint8List data1;
  late Uint8List data2;
  String compareString = "Not compared yet";
  @override
  Widget build(BuildContext context) {
    return Row(
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        Column(
          children: [
            ElevatedButton(
              onPressed: () async {
                widget.cameraCtrl.takePicture().then((f) {
                  return f.readAsBytes();
                }).then((d) {
                  data1 = d;
                  setState(() {
                    bImageCaptured1 = true;
                  });
                });
              },
              child: const Text("Capture Image 1"),
            ),
            SizedBox(
              height: 150,
              child: bImageCaptured1
                  ? Image.memory(data1)
                  : const Text("No image captured."),
            ),
          ],
        ),
        Column(
          children: [
            ElevatedButton(
              onPressed: bImageCaptured1
                  ? () async {
                      widget.cameraCtrl.takePicture().then((f) {
                        return f.readAsBytes();
                      }).then((d) {
                        data2 = d;
                        setState(() {
                          bImageCaptured2 = true;
                        });
                      });
                    }
                  : null,
              child: const Text("Capture Image 2"),
            ),
            SizedBox(
              height: 150,
              child: bImageCaptured2
                  ? Image.memory(data2)
                  : const Text("No image captured."),
            ),
          ],
        ),
        Column(
          children: [
            ElevatedButton(
              onPressed: bImageCaptured1 && bImageCaptured2
                  ? () {
                      final img1 = base64UrlEncode(data1);
                      final img2 = base64UrlEncode(data2);
                      http.post(
                          Uri(
                              scheme: "http",
                              path: "/compare",
                              queryParameters: {"img1": img1, "img2": img2}),
                          headers: {"Content-Type": "application/json"}).then(
                        (res) {
                          setState(
                            () {
                              compareString = (res.statusCode == 200)
                                  ? res.body
                                  : "${res.statusCode} ${res.reasonPhrase} ${res.body}";
                            },
                          );
                        },
                      );
                    }
                  : null,
              child: const Text("Compare"),
            ),
            SizedBox(
              width: 150,
              height: 150,
              child: Text(compareString),
            ),
          ],
        ),
      ],
    );
  }
}
