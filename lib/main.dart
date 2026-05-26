import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

void main() => runApp(const App());

const cB = Color(0xFF0A1628);
const cB2 = Color(0xFF0D1F3C);
const cBl = Color(0xFF1A3A6B);
const cAc = Color(0xFF4A90E2);
const cAc2 = Color(0xFF64B5F6);
const cG = Color(0xFF00E676);
const cYe = Color(0xFFFFD600);
const cRe = Color(0xFFFF5252);
const cWh = Color(0xFFE8EEF7);
const cDg = Color(0xFF4A6FA5);
const cBr = Color(0xFF1E3A5F);

final _client = HttpClient()..badCertificateCallback = (_, __, ___) => true;

Future<String?> _get(String url, {int timeout = 10}) async {
  try {
    final req = await _client.getUrl(Uri.parse(url));
    req.headers.set('User-Agent', 'Mozilla/5.0 (compatible; MirrorFinder/1.0)');
    final res = await req.close().timeout(Duration(seconds: timeout));
    return await res.transform(utf8.decoder).join();
  } catch (_) { return null; }
}

class MirrorResult {
  String domain = '';
  String ip = '';
  String country = '';
  String isp = '';
  String asn = '';
  List<String> mirrors = [];
  bool loading = false;
  String error = '';
}

Future<MirrorResult> findMirrors(String input) async {
  final r = MirrorResult();

  // Normalize input
  var domain = input.trim()
    .replaceAll(RegExp(r'^https?://'), '')
    .replaceAll(RegExp(r'/.*$'), '')
    .replaceAll(RegExp(r':\d+$'), '')
    .trim();
  r.domain = domain;

  // Step 1: Resolve IP
  try {
    final addresses = await InternetAddress.lookup(domain)
      .timeout(const Duration(seconds: 5));
    if (addresses.isNotEmpty) r.ip = addresses.first.address;
  } catch (_) {}

  // Step 2: Get IP info
  if (r.ip.isNotEmpty) {
    try {
      final body = await _get('http://ip-api.com/json/' + r.ip + '?fields=country,isp,org,as');
      if (body != null) {
        final data = jsonDecode(body) as Map<String, dynamic>;
        r.country = data['country'] ?? '';
        r.isp = data['isp'] ?? '';
        r.asn = data['as'] ?? '';
      }
    } catch (_) {}
  }

  // Step 3: Reverse IP lookup via HackerTarget
  final target = r.ip.isNotEmpty ? r.ip : domain;
  try {
    final body = await _get('https://api.hackertarget.com/reverseiplookup/?q=' + target, timeout: 15);
    if (body != null && !body.contains('error') && !body.contains('API count')) {
      final lines = body.split('\n')
        .map((l) => l.trim())
        .where((l) => l.isNotEmpty && l != domain && _isDomain(l))
        .toSet()
        .toList();
      r.mirrors.addAll(lines);
    }
  } catch (_) {}

  // Step 4: Also check HackerTarget hostsearch
  try {
    final body = await _get('https://api.hackertarget.com/hostsearch/?q=' + domain, timeout: 15);
    if (body != null && !body.contains('error') && !body.contains('API count')) {
      final lines = body.split('\n')
        .where((l) => l.contains(','))
        .map((l) => l.split(',')[0].trim())
        .where((l) => l.isNotEmpty && l != domain && _isDomain(l))
        .toSet()
        .toList();
      for (final l in lines) {
        if (!r.mirrors.contains(l)) r.mirrors.add(l);
      }
    }
  } catch (_) {}

  // Remove duplicates and sort
  r.mirrors = r.mirrors.toSet().toList()..sort();

  return r;
}

bool _isDomain(String s) {
  return s.contains('.') &&
    !s.contains(' ') &&
    !s.startsWith('.') &&
    s.length > 3 &&
    RegExp(r'^[a-zA-Z0-9\-\.]+$').hasMatch(s);
}

class App extends StatelessWidget {
  const App({super.key});
  @override
  Widget build(BuildContext context) => MaterialApp(
    title: 'JsusTVespejos',
    debugShowCheckedModeBanner: false,
    theme: ThemeData(
      scaffoldBackgroundColor: cB,
      colorScheme: const ColorScheme.dark(primary: cAc),
      fontFamily: 'monospace',
    ),
    home: const HomeScreen(),
  );
}

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});
  @override
  State<HomeScreen> createState() => _HS();
}

class _HS extends State<HomeScreen> with TickerProviderStateMixin {
  final _ctrl = TextEditingController();
  MirrorResult? _result;
  bool _loading = false;
  final _history = <MirrorResult>[];

  late AnimationController _pulseAc;
  late Animation<double> _pulse;
  final _rnd = Random();
  List<List<double>> _drops = [];
  List<List<String>> _chars = [];
  Timer? _matTimer;

  @override
  void initState() {
    super.initState();
    _pulseAc = AnimationController(vsync: this, duration: const Duration(milliseconds: 1500))..repeat(reverse: true);
    _pulse = Tween<double>(begin: 0.4, end: 1.0).animate(_pulseAc);
    _initMatrix();
    _matTimer = Timer.periodic(const Duration(milliseconds: 80), (_) => _tickMatrix());
  }

  void _initMatrix() {
    const cols = 28, rows = 60;
    _drops = List.generate(cols, (_) => List.generate(rows, (_) => 0.0));
    _chars = List.generate(cols, (_) => List.generate(rows, (_) {
      const ch = '01ABCDEFabcdef<>[]';
      return ch[_rnd.nextInt(ch.length)];
    }));
  }

  void _tickMatrix() {
    if (!mounted) return;
    setState(() {
      for (var c = 0; c < _drops.length; c++) {
        if (_rnd.nextDouble() < 0.02) _drops[c][0] = 1.0;
        for (var r = _drops[c].length - 1; r > 0; r--) {
          if (_drops[c][r-1] > 0.5 && _drops[c][r] < 0.1) _drops[c][r] = _drops[c][r-1] * 0.92;
          if (_drops[c][r] > 0) { _drops[c][r] -= 0.02; }
        }
        _drops[c][0] *= 0.9;
      }
    });
  }

  @override
  void dispose() {
    _pulseAc.dispose();
    _matTimer?.cancel();
    super.dispose();
  }

  void _toast(String m) => ScaffoldMessenger.of(context).showSnackBar(SnackBar(
    content: Text(m, style: const TextStyle(color: cWh)),
    backgroundColor: cBl,
    duration: const Duration(seconds: 2),
    behavior: SnackBarBehavior.floating,
    shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8),
      side: const BorderSide(color: cAc)),
  ));

  Future<void> _search() async {
    final input = _ctrl.text.trim();
    if (input.isEmpty) { _toast('Ingresa un dominio o URL'); return; }
    setState(() { _loading = true; _result = null; });
    final r = await findMirrors(input);
    setState(() {
      _result = r;
      _loading = false;
      if (!_history.any((h) => h.domain == r.domain)) {
        _history.insert(0, r);
        if (_history.length > 10) _history.removeLast();
      }
    });
  }

  @override
  Widget build(BuildContext context) => Scaffold(
    backgroundColor: cB,
    body: Stack(children: [
      Positioned.fill(child: CustomPaint(painter: _MP(_drops, _chars))),
      Positioned.fill(child: Container(decoration: BoxDecoration(
        gradient: RadialGradient(center: Alignment.center, radius: 1.2,
          colors: [Colors.transparent, cB.withOpacity(0.8)])))),
      SafeArea(child: Column(children: [
        _header(),
        Expanded(child: SingleChildScrollView(
          padding: const EdgeInsets.all(14),
          child: Column(children: [
            _inputCard(),
            const SizedBox(height: 14),
            if (_loading) _loadingCard(),
            if (_result != null && !_loading) _resultCard(),
            if (_history.isNotEmpty && _result == null && !_loading) _historySection(),
          ]))),
      ])),
    ]),
  );

  Widget _header() => Container(
    padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
    decoration: BoxDecoration(
      color: cB2.withOpacity(0.95),
      border: Border(bottom: BorderSide(color: cBl))),
    child: Row(children: [
      Container(
        width: 44, height: 44,
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: cAc.withOpacity(0.4)),
          boxShadow: [BoxShadow(color: cAc.withOpacity(0.2), blurRadius: 12)]),
        child: ClipRRect(borderRadius: BorderRadius.circular(11),
          child: Image.asset('android-icon/icon.png',
            errorBuilder: (_, __, ___) => Container(color: cB2,
              child: const Center(child: Text('📡', style: TextStyle(fontSize: 22))))))),
      const SizedBox(width: 12),
      Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        ShaderMask(
          shaderCallback: (b) => LinearGradient(colors: [cAc, cAc2]).createShader(b),
          child: const Text('JsusTVespejos', style: TextStyle(fontSize: 18,
            fontWeight: FontWeight.bold, color: Colors.white, letterSpacing: 1))),
        Text('IPTV Mirror Finder v1.0',
          style: TextStyle(fontSize: 9, color: cDg, letterSpacing: 2)),
      ])),
      AnimatedBuilder(animation: _pulse, builder: (_, __) => Container(
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
        decoration: BoxDecoration(
          color: (_loading ? cYe : cAc).withOpacity(0.1),
          borderRadius: BorderRadius.circular(20),
          border: Border.all(color: (_loading ? cYe : cAc).withOpacity(0.4))),
        child: Row(mainAxisSize: MainAxisSize.min, children: [
          Container(width: 6, height: 6, decoration: BoxDecoration(
            shape: BoxShape.circle,
            color: _loading ? cYe : cAc,
            boxShadow: [BoxShadow(color: (_loading ? cYe : cAc).withOpacity(_pulse.value), blurRadius: 6)])),
          const SizedBox(width: 5),
          Text(_loading ? 'SCAN' : 'IDLE',
            style: TextStyle(fontSize: 9, color: _loading ? cYe : cAc,
              letterSpacing: 1.5, fontWeight: FontWeight.bold)),
        ]))),
    ]));

  Widget _inputCard() => Container(
    decoration: BoxDecoration(
      color: cB2.withOpacity(0.9),
      borderRadius: BorderRadius.circular(12),
      border: Border.all(color: cBl),
      boxShadow: [BoxShadow(color: cAc.withOpacity(0.05), blurRadius: 15)]),
    child: Column(children: [
      Container(
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
        decoration: BoxDecoration(
          color: cAc.withOpacity(0.06),
          borderRadius: const BorderRadius.vertical(top: Radius.circular(12)),
          border: Border(bottom: BorderSide(color: cBl))),
        child: Row(children: [
          const Text('🔍', style: TextStyle(fontSize: 14)),
          const SizedBox(width: 8),
          const Text('BUSCAR ESPEJOS', style: TextStyle(fontSize: 10, color: cDg,
            letterSpacing: 2, fontWeight: FontWeight.bold)),
          const Spacer(),
          GestureDetector(
            onTap: () async {
              final data = await Clipboard.getData('text/plain');
              if (data?.text != null) { _ctrl.text = data!.text!; _toast('Pegado'); }
            },
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
              decoration: BoxDecoration(
                color: cAc.withOpacity(0.1), borderRadius: BorderRadius.circular(6),
                border: Border.all(color: cAc.withOpacity(0.3))),
              child: const Text('📋 PEGAR', style: TextStyle(fontSize: 9, color: cAc,
                fontWeight: FontWeight.bold)))),
        ])),
      Padding(padding: const EdgeInsets.all(12), child: TextField(
        controller: _ctrl,
        style: const TextStyle(color: cWh, fontSize: 13),
        onSubmitted: (_) => _search(),
        decoration: InputDecoration(
          hintText: 'http://servidor.com:8080  o  dominio.com',
          hintStyle: TextStyle(color: cDg.withOpacity(0.5), fontSize: 12),
          filled: true, fillColor: Colors.black26,
          prefixIcon: const Icon(Icons.language, color: cDg, size: 18),
          border: OutlineInputBorder(borderRadius: BorderRadius.circular(8),
            borderSide: BorderSide(color: cBl)),
          enabledBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(8),
            borderSide: BorderSide(color: cBl)),
          focusedBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(8),
            borderSide: const BorderSide(color: cAc, width: 1.5)),
          contentPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 12)))),
      Padding(padding: const EdgeInsets.fromLTRB(12, 0, 12, 12), child:
        AnimatedBuilder(animation: _pulse, builder: (_, __) => GestureDetector(
          onTap: _search,
          child: Container(
            width: double.infinity, padding: const EdgeInsets.symmetric(vertical: 14),
            decoration: BoxDecoration(
              gradient: LinearGradient(colors: [cAc.withOpacity(0.15), cAc2.withOpacity(0.25)]),
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: cAc.withOpacity(0.6)),
              boxShadow: [BoxShadow(color: cAc.withOpacity(_pulse.value * 0.2), blurRadius: 15)]),
            child: const Row(mainAxisAlignment: MainAxisAlignment.center, children: [
              Text('📡', style: TextStyle(fontSize: 16)),
              SizedBox(width: 8),
              Text('BUSCAR ESPEJOS', style: TextStyle(fontSize: 13,
                fontWeight: FontWeight.bold, letterSpacing: 2, color: cAc2)),
            ]))))),
    ]));

  Widget _loadingCard() => Container(
    padding: const EdgeInsets.all(30),
    decoration: BoxDecoration(
      color: cB2.withOpacity(0.9), borderRadius: BorderRadius.circular(12),
      border: Border.all(color: cBl)),
    child: Column(children: [
      AnimatedBuilder(animation: _pulse, builder: (_, __) => Container(
        width: 60, height: 60,
        decoration: BoxDecoration(
          shape: BoxShape.circle,
          border: Border.all(color: cAc.withOpacity(_pulse.value), width: 2),
          boxShadow: [BoxShadow(color: cAc.withOpacity(_pulse.value * 0.3), blurRadius: 20)]),
        child: const Center(child: Text('📡', style: TextStyle(fontSize: 28))))),
      const SizedBox(height: 16),
      const Text('BUSCANDO ESPEJOS...', style: TextStyle(fontSize: 12, color: cAc2,
        letterSpacing: 3, fontWeight: FontWeight.bold)),
      const SizedBox(height: 6),
      Text('Resolviendo IP y dominios relacionados...',
        style: TextStyle(fontSize: 9, color: cDg)),
      const SizedBox(height: 12),
      const LinearProgressIndicator(color: cAc, backgroundColor: cBl),
    ]));

  Widget _resultCard() {
    final r = _result!;
    return Column(children: [
      // Info card
      Container(
        decoration: BoxDecoration(
          color: cB2.withOpacity(0.9), borderRadius: BorderRadius.circular(12),
          border: Border(left: const BorderSide(color: cAc, width: 3),
            top: BorderSide(color: cAc.withOpacity(0.2)),
            right: BorderSide(color: cAc.withOpacity(0.1)),
            bottom: BorderSide(color: cAc.withOpacity(0.1))),
          boxShadow: [BoxShadow(color: cAc.withOpacity(0.08), blurRadius: 15)]),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
            decoration: BoxDecoration(
              color: cAc.withOpacity(0.07),
              borderRadius: const BorderRadius.vertical(top: Radius.circular(12)),
              border: Border(bottom: BorderSide(color: cAc.withOpacity(0.15)))),
            child: Row(children: [
              const Text('🌐', style: TextStyle(fontSize: 16)),
              const SizedBox(width: 8),
              Expanded(child: Text(r.domain,
                style: const TextStyle(fontSize: 14, color: cAc2,
                  fontWeight: FontWeight.bold))),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                decoration: BoxDecoration(
                  color: cG.withOpacity(0.1), borderRadius: BorderRadius.circular(10),
                  border: Border.all(color: cG.withOpacity(0.3))),
                child: Text('${r.mirrors.length} espejos',
                  style: const TextStyle(fontSize: 9, color: cG, fontWeight: FontWeight.bold))),
            ])),
          Padding(padding: const EdgeInsets.all(14), child: Column(
            crossAxisAlignment: CrossAxisAlignment.start, children: [
            if (r.ip.isNotEmpty) _infoRow('🔢 IP', r.ip, cAc2),
            if (r.country.isNotEmpty) _infoRow('📍 País', r.country, cYe),
            if (r.isp.isNotEmpty) _infoRow('🏢 ISP', r.isp, cDg),
            if (r.asn.isNotEmpty) _infoRow('🔗 ASN', r.asn, cDg),
          ])),
        ])),
      const SizedBox(height: 10),
      // Mirrors list
      if (r.mirrors.isEmpty)
        Container(
          padding: const EdgeInsets.all(20),
          decoration: BoxDecoration(
            color: cB2.withOpacity(0.9), borderRadius: BorderRadius.circular(12),
            border: Border.all(color: cBl)),
          child: Column(children: [
            const Text('🔍', style: TextStyle(fontSize: 32)),
            const SizedBox(height: 8),
            const Text('No se encontraron espejos', style: TextStyle(fontSize: 12, color: cWh)),
            const SizedBox(height: 4),
            Text('Este servidor no comparte IP con otros dominios conocidos',
              style: TextStyle(fontSize: 9, color: cDg), textAlign: TextAlign.center),
          ]))
      else ...[
        Container(
          decoration: BoxDecoration(
            color: cB2.withOpacity(0.9), borderRadius: BorderRadius.circular(12),
            border: Border.all(color: cBl)),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
              decoration: BoxDecoration(
                color: cAc.withOpacity(0.05),
                borderRadius: const BorderRadius.vertical(top: Radius.circular(12)),
                border: Border(bottom: BorderSide(color: cBl))),
              child: Row(children: [
                const Text('📡', style: TextStyle(fontSize: 14)),
                const SizedBox(width: 8),
                const Text('DOMINIOS ESPEJO', style: TextStyle(fontSize: 10, color: cDg,
                  letterSpacing: 2, fontWeight: FontWeight.bold)),
                const Spacer(),
                GestureDetector(
                  onTap: () {
                    final all = r.mirrors.join('\n');
                    Clipboard.setData(ClipboardData(text: all));
                    _toast('${r.mirrors.length} espejos copiados');
                  },
                  child: Container(
                    padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                    decoration: BoxDecoration(
                      color: cAc.withOpacity(0.1), borderRadius: BorderRadius.circular(6),
                      border: Border.all(color: cAc.withOpacity(0.3))),
                    child: const Text('📋 COPIAR TODO', style: TextStyle(fontSize: 9, color: cAc,
                      fontWeight: FontWeight.bold)))),
              ])),
            ...r.mirrors.asMap().entries.map((e) => Container(
              padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
              decoration: BoxDecoration(
                border: Border(bottom: BorderSide(
                  color: e.key < r.mirrors.length - 1 ? cBl : Colors.transparent))),
              child: Row(children: [
                Container(width: 6, height: 6, decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  color: cAc.withOpacity(0.6))),
                const SizedBox(width: 10),
                Expanded(child: Text(e.value,
                  style: const TextStyle(fontSize: 12, color: cWh))),
                GestureDetector(
                  onTap: () {
                    Clipboard.setData(ClipboardData(text: e.value));
                    _toast('Copiado: ' + e.value);
                  },
                  child: Container(
                    padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                    decoration: BoxDecoration(
                      color: cAc.withOpacity(0.08), borderRadius: BorderRadius.circular(4),
                      border: Border.all(color: cAc.withOpacity(0.2))),
                    child: const Text('CPY', style: TextStyle(fontSize: 8, color: cAc,
                      fontWeight: FontWeight.bold)))),
              ]))),
          ])),
      ],
      const SizedBox(height: 10),
      // Actions
      Row(children: [
        Expanded(child: _btn('🔄 NUEVA BÚSQUEDA', cAc, () {
          setState(() { _result = null; _ctrl.clear(); });
        })),
        const SizedBox(width: 8),
        Expanded(child: _btn('📋 COPIAR REPORTE', cG, () {
          final buf = StringBuffer();
          buf.writeln('DOMINIO: ' + r.domain);
          if (r.ip.isNotEmpty) buf.writeln('IP: ' + r.ip);
          if (r.country.isNotEmpty) buf.writeln('PAIS: ' + r.country);
          if (r.isp.isNotEmpty) buf.writeln('ISP: ' + r.isp);
          buf.writeln('ESPEJOS: ' + r.mirrors.length.toString());
          if (r.mirrors.isNotEmpty) {
            buf.writeln('---');
            for (final m in r.mirrors) buf.writeln(m);
          }
          Clipboard.setData(ClipboardData(text: buf.toString()));
          _toast('Reporte copiado');
        })),
      ]),
    ]);
  }

  Widget _historySection() => Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
    Padding(padding: const EdgeInsets.symmetric(vertical: 8), child: Row(children: [
      Container(width: 2, height: 12, color: cDg, margin: const EdgeInsets.only(right: 8)),
      Text('HISTORIAL', style: TextStyle(fontSize: 10, color: cDg,
        letterSpacing: 3, fontWeight: FontWeight.bold)),
    ])),
    for (final h in _history) GestureDetector(
      onTap: () { _ctrl.text = h.domain; _search(); },
      child: Container(
        margin: const EdgeInsets.only(bottom: 6),
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
        decoration: BoxDecoration(
          color: cB2.withOpacity(0.8), borderRadius: BorderRadius.circular(8),
          border: Border.all(color: cBl)),
        child: Row(children: [
          const Text('📡', style: TextStyle(fontSize: 14)),
          const SizedBox(width: 10),
          Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text(h.domain, style: const TextStyle(fontSize: 12, color: cWh)),
            if (h.ip.isNotEmpty) Text(h.ip, style: TextStyle(fontSize: 9, color: cDg)),
          ])),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
            decoration: BoxDecoration(
              color: cG.withOpacity(0.1), borderRadius: BorderRadius.circular(10),
              border: Border.all(color: cG.withOpacity(0.3))),
            child: Text(h.mirrors.length.toString() + ' espejos',
              style: const TextStyle(fontSize: 9, color: cG, fontWeight: FontWeight.bold))),
        ]))),
  ]);

  Widget _infoRow(String label, String val, Color c) => Padding(
    padding: const EdgeInsets.only(bottom: 6),
    child: Row(children: [
      Text(label + ':  ', style: TextStyle(fontSize: 10, color: cDg)),
      Expanded(child: Text(val, style: TextStyle(fontSize: 10, color: c,
        fontWeight: FontWeight.w500), overflow: TextOverflow.ellipsis)),
    ]));

  Widget _btn(String label, Color c, VoidCallback onTap) => GestureDetector(
    onTap: onTap,
    child: Container(
      padding: const EdgeInsets.symmetric(vertical: 12),
      decoration: BoxDecoration(
        color: c.withOpacity(0.1), borderRadius: BorderRadius.circular(8),
        border: Border.all(color: c.withOpacity(0.4))),
      child: Text(label, textAlign: TextAlign.center,
        style: TextStyle(fontSize: 11, color: c,
          fontWeight: FontWeight.bold, letterSpacing: 1))));
}

class _MP extends CustomPainter {
  final List<List<double>> drops;
  final List<List<String>> chars;
  _MP(this.drops, this.chars);
  @override
  void paint(Canvas canvas, Size size) {
    for (var c = 0; c < drops.length; c++) {
      for (var r = 0; r < drops[c].length; r++) {
        final a = drops[c][r];
        if (a <= 0.05) continue;
        final tp = TextPainter(
          text: TextSpan(text: chars[c][r],
            style: TextStyle(color: const Color(0xFF4A90E2).withOpacity(a * 0.2),
              fontSize: 11, fontFamily: 'monospace')),
          textDirection: TextDirection.ltr)..layout();
        tp.paint(canvas, Offset(c * 14.0, r * 14.0));
      }
    }
  }
  @override
  bool shouldRepaint(_MP old) => true;
}
