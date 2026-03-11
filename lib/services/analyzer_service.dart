import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'package:path/path.dart' as p;
import '../models/decryption_info.dart';
import 'dex_parser.dart';

/// Serviço que analisa arquivos .smali, System.json e .dex em busca de chaves
class AnalyzerService {
  final void Function(String message) onLog;

  AnalyzerService({required this.onLog});

  // ─────────────────────────────────────────────────────────────────
  // Palavras-chave que indicam classes de criptografia
  // ─────────────────────────────────────────────────────────────────
  static const List<String> _cryptoKeywords = [
    'encrypt',
    'decrypt',
    'cipher',
    'crypto',
    'encryptedassets',
    'assetdecryptor',
    'secretkey',
    'aes',
  ];

  // ─────────────────────────────────────────────────────────────────
  // Análise principal
  // ─────────────────────────────────────────────────────────────────

  Future<EncryptionInfo?> analyze(String decompiledDir) async {
    onLog('🔍 Buscando arquivos smali...');

    final smaliDirs = _findSmaliDirs(decompiledDir);

    if (smaliDirs.isEmpty) {
      onLog('⚠️  Nenhuma pasta smali encontrada.');
      onLog('   Tentando métodos alternativos de detecção...');
      return _tryDirectAssetAnalysis(decompiledDir);
    }

    onLog('📂 Encontradas ${smaliDirs.length} pasta(s) smali');

    // 1ª passagem: arquivos com nome suspeito
    final cryptoFiles = <File>[];
    for (final dir in smaliDirs) {
      final found = await _findByFileName(dir);
      cryptoFiles.addAll(found);
    }

    // 2ª passagem: busca por conteúdo se não achou pelo nome
    if (cryptoFiles.isEmpty) {
      onLog('⚠️  Nenhuma classe crypto por nome. Buscando por conteúdo...');
      for (final dir in smaliDirs) {
        final found = await _findByContent(dir);
        cryptoFiles.addAll(found);
        if (cryptoFiles.length >= 5) break;
      }
    }

    if (cryptoFiles.isEmpty) {
      onLog('❌ Nenhuma classe de criptografia encontrada no smali.');
      onLog('   Tentando métodos alternativos...');
      return _tryDirectAssetAnalysis(decompiledDir);
    }

    onLog('✅ ${cryptoFiles.length} arquivo(s) candidato(s) encontrado(s)');

    // Extrai chave e tipo de cada arquivo
    for (final file in cryptoFiles) {
      onLog('🔎 Analisando: ${p.basename(file.path)}');
      final content = file.readAsStringSync(encoding: _latin1);

      final key = _extractSecretKey(content);
      final type = _detectEncryptionType(content);

      if (key != null) {
        final shortKey = key.length > 20 ? '${key.substring(0, 20)}...' : key;
        onLog('🔑 Chave encontrada: $shortKey');
        onLog('🔒 Tipo: $type');

        return EncryptionInfo(
          secretKey: key,
          encryptionType: type,
          sourceFile: p.basename(file.path),
        );
      }
    }

    onLog('⚠️  Chave não detectada no smali. Tentando métodos alternativos...');
    return _tryDirectAssetAnalysis(decompiledDir);
  }

  // ─────────────────────────────────────────────────────────────────
  // Fallback: análise sem smali
  // ─────────────────────────────────────────────────────────────────

  Future<EncryptionInfo?> _tryDirectAssetAnalysis(String dir) async {
    // Método 1: System.json (RPG Maker MV / MZ)
    final systemJsonResult = await _findSystemJson(dir);
    if (systemJsonResult != null) return systemJsonResult;

    // Método 2: varredura de strings em arquivos .dex
    final dexResult = await _scanDexFiles(dir);
    if (dexResult != null) return dexResult;

    onLog('❌ Sem smali não é possível extrair a chave automaticamente.');
    onLog('💡 Dica: insira a chave manualmente na seção "Chave Manual".');
    return null;
  }

  // ─────────────────────────────────────────────────────────────────
  // Método 1 — System.json (RPG Maker MV / MZ)
  // O campo "encryptionKey" contém a chave em hex (ex: "a1b2c3d4e5f6...")
  // ─────────────────────────────────────────────────────────────────

  Future<EncryptionInfo?> _findSystemJson(String dir) async {
    onLog('📄 Procurando System.json (RPG Maker MV/MZ)...');

    // Caminhos mais comuns primeiro (rápido)
    final priorityCandidates = [
      p.join(dir, 'assets', 'www', 'data', 'System.json'),
      p.join(dir, 'assets', 'www', 'data', 'system.json'),
      p.join(dir, 'www', 'data', 'System.json'),
      p.join(dir, 'www', 'data', 'system.json'),
      p.join(dir, 'assets', 'data', 'System.json'),
    ];

    for (final path in priorityCandidates) {
      final file = File(path);
      if (file.existsSync()) {
        final result = await _parseSystemJson(file);
        if (result != null) return result;
      }
    }

    // Busca recursiva completa como fallback
    final rootDir = Directory(dir);
    if (!rootDir.existsSync()) return null;

    try {
      await for (final entity in rootDir.list(recursive: true)) {
        if (entity is File &&
            p.basename(entity.path).toLowerCase() == 'system.json') {
          final result = await _parseSystemJson(entity);
          if (result != null) return result;
        }
      }
    } catch (_) {}

    return null;
  }

  Future<EncryptionInfo?> _parseSystemJson(File file) async {
    try {
      final content = await file.readAsString(encoding: utf8);
      final json = jsonDecode(content);

      if (json is! Map<String, dynamic>) return null;

      // Campo principal: "encryptionKey" (RPG Maker MV/MZ padrão)
      for (final key in ['encryptionKey', 'EncryptionKey', 'encryption_key']) {
        final value = json[key];
        if (value is String && value.isNotEmpty) {
          final shortVal =
              value.length > 20 ? '${value.substring(0, 20)}...' : value;
          onLog('✅ Chave encontrada em System.json: $shortVal');
          onLog('🔒 Tipo: AES-CBC (padrão RPG Maker MV/MZ)');
          return EncryptionInfo(
            secretKey: value,
            encryptionType: 'AES-CBC',
            sourceFile: 'System.json',
          );
        }
      }
    } catch (e) {
      // System.json pode estar vazio ou malformado em alguns jogos
    }
    return null;
  }

  // ─────────────────────────────────────────────────────────────────
  // Método 2 — Parser DEX binário (sem Java)
  //
  // O formato DEX armazena todas as constantes de string em uma tabela
  // indexada. Ao parsear o header do DEX (offsets documentados), extraímos
  // diretamente os literais de string — o mesmo resultado que baksmali/
  // apktool produziria, sem nenhuma dependência externa.
  // ─────────────────────────────────────────────────────────────────

  Future<EncryptionInfo?> _scanDexFiles(String dir) async {
    onLog('🔬 Parseando arquivos .dex (formato binário DEX)...');

    final rootDir = Directory(dir);
    if (!rootDir.existsSync()) return null;

    // Prioridade: classes.dex, classes2.dex, classes3.dex (ordem de relevância)
    final dexFiles = <File>[];
    for (final name in ['classes.dex', 'classes2.dex', 'classes3.dex',
                         'classes4.dex', 'classes5.dex']) {
      final f = File(p.join(dir, name));
      if (f.existsSync()) dexFiles.add(f);
    }

    // Busca recursiva se não encontrou na raiz (APK com estrutura diferente)
    if (dexFiles.isEmpty) {
      try {
        await for (final entity in rootDir.list(recursive: true)) {
          if (entity is File && p.extension(entity.path) == '.dex') {
            dexFiles.add(entity);
            if (dexFiles.length >= 6) break;
          }
        }
      } catch (_) {}
    }

    if (dexFiles.isEmpty) {
      onLog('⚠️  Nenhum arquivo .dex encontrado no APK extraído.');
      return null;
    }

    onLog('   ${dexFiles.length} arquivo(s) .dex encontrado(s)');

    for (final dex in dexFiles) {
      final result = await _extractKeyFromDex(dex);
      if (result != null) return result;
    }

    return null;
  }

  /// Usa [DexParser] para extrair strings do formato binário DEX e
  /// identificar candidatos a chave de criptografia.
  Future<EncryptionInfo?> _extractKeyFromDex(File dexFile) async {
    try {
      final stat = dexFile.statSync();
      // Lê até 20MB para DEX grandes (classes.dex de jogos pode ser volumoso)
      final maxBytes = min(stat.size, 20 * 1024 * 1024);
      final raf = dexFile.openSync();
      final bytes = raf.readSync(maxBytes);
      raf.closeSync();

      final parser = DexParser(bytes);

      if (!parser.isValidDex) {
        // Não é DEX válido, silenciosamente ignora
        return null;
      }

      // Verifica se este DEX tem referências a crypto antes de varrer tudo
      final hasCrypto = parser.hasCryptoReferences();
      if (!hasCrypto) {
        // DEX sem referências a criptografia — provavelmente não tem a chave
        return null;
      }

      final encType = parser.detectEncryptionType();
      onLog('   📂 ${p.basename(dexFile.path)}: DEX v${parser.version}, '
            'possui referências crypto ($encType)');

      // Extrai candidatos a chave da tabela de strings
      final keyCandidates = parser.extractAllStrings(filterForKeys: true);

      if (keyCandidates.isEmpty) {
        onLog('   ⚠️  Nenhum candidato a chave nas strings do DEX.');
        return null;
      }

      onLog('   🔎 ${keyCandidates.length} candidato(s) encontrado(s)');

      // Retorna o primeiro candidato válido
      for (final candidate in keyCandidates) {
        final shortKey = candidate.length > 20
            ? '${candidate.substring(0, 20)}...'
            : candidate;
        onLog('🔑 Chave encontrada em ${p.basename(dexFile.path)}: $shortKey');
        onLog('🔒 Tipo: $encType (via parser DEX)');
        return EncryptionInfo(
          secretKey: candidate,
          encryptionType: encType,
          sourceFile: p.basename(dexFile.path),
        );
      }
    } catch (e) {
      onLog('   ⚠️  Erro ao parsear ${p.basename(dexFile.path)}: $e');
    }
    return null;
  }

  // ─────────────────────────────────────────────────────────────────
  // Helpers privados — smali
  // ─────────────────────────────────────────────────────────────────

  List<Directory> _findSmaliDirs(String root) {
    final rootDir = Directory(root);
    if (!rootDir.existsSync()) return [];

    return rootDir
        .listSync()
        .whereType<Directory>()
        .where((d) => p.basename(d.path).startsWith('smali'))
        .toList();
  }

  Future<List<File>> _findByFileName(Directory smaliDir) async {
    final result = <File>[];
    try {
      await for (final entity in smaliDir.list(recursive: true)) {
        if (entity is File && entity.path.endsWith('.smali')) {
          final name = p.basenameWithoutExtension(entity.path).toLowerCase();
          if (_cryptoKeywords.any((kw) => name.contains(kw))) {
            result.add(entity);
          }
        }
      }
    } catch (_) {}
    return result;
  }

  Future<List<File>> _findByContent(Directory smaliDir) async {
    final result = <File>[];
    try {
      await for (final entity in smaliDir.list(recursive: true)) {
        if (entity is File && entity.path.endsWith('.smali')) {
          try {
            final content = entity.readAsStringSync(encoding: _latin1);
            if (content.contains('.enc"') ||
                content.toLowerCase().contains('decrypt')) {
              result.add(entity);
              if (result.length >= 5) break;
            }
          } catch (_) {}
        }
      }
    } catch (_) {}
    return result;
  }

  /// Extrai a secret key de um arquivo .smali
  String? _extractSecretKey(String content) {
    // Padrão 1: const-string com valor longo
    final pattern1 = RegExp(r'const-string\s+\w+,\s+"([^"]{16,})"');
    final match1 = pattern1.firstMatch(content);
    if (match1 != null) {
      final candidate = match1.group(1)!;
      if (candidate.length >= 16) return candidate;
    }

    // Padrão 2: .field SECRET_KEY:Ljava/lang/String; = "..."
    final pattern2 = RegExp(
      r'\.field.*SECRET.*:Ljava/lang/String;\s*=\s*"([^"]{16,})"',
      caseSensitive: false,
    );
    final match2 = pattern2.firstMatch(content);
    if (match2 != null) return match2.group(1);

    // Padrão 3: qualquer string alfanumérica longa (≥20 chars)
    final pattern3 = RegExp(r'"([A-Za-z0-9+/=]{20,})"');
    for (final match in pattern3.allMatches(content)) {
      final s = match.group(1)!;
      if (_looksLikeKey(s)) return s;
    }

    return null;
  }

  bool _looksLikeKey(String s) {
    if (s.contains('.') || s.contains('/') || s.contains('\\')) return false;
    if (s.length < 16) return false;
    final hasDigit = s.contains(RegExp(r'\d'));
    final hasLetter = s.contains(RegExp(r'[A-Za-z]'));
    return hasDigit && hasLetter;
  }

  /// Detecta o tipo de criptografia em um arquivo .smali
  String _detectEncryptionType(String content) {
    if (content.contains('AES/CBC')) return 'AES-CBC';
    if (content.contains('AES/ECB')) return 'AES-ECB';
    if (content.contains('AES') ||
        content.contains('javax/crypto/Cipher')) return 'AES';
    if (content.contains('xor-int') || content.contains('xor-long')) {
      return 'XOR';
    }
    return 'AES-CBC'; // fallback padrão
  }

  static final _latin1 = SystemEncoding();
}
