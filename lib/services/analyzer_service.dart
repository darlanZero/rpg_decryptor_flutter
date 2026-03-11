import 'dart:io';
import 'package:path/path.dart' as p;
import '../models/decryption_info.dart';

/// Serviço que analisa arquivos .smali em busca de chaves de criptografia
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
      onLog('   Tentando busca nos assets extraídos...');
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
      onLog('❌ Nenhuma classe de criptografia encontrada.');
      return null;
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

    onLog('⚠️  Chave não detectada automaticamente.');
    return null;
  }

  // ─────────────────────────────────────────────────────────────────
  // Helpers privados
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

  /// Fallback: analisa assets extraídos diretamente
  Future<EncryptionInfo?> _tryDirectAssetAnalysis(String dir) async {
    final assetsDir = Directory(p.join(dir, 'assets'));
    if (!assetsDir.existsSync()) return null;

    onLog('📁 Tentando busca em assets/...');
    // Sem smali, não temos como extrair a chave automaticamente
    onLog('❌ Sem smali não é possível extrair a chave automaticamente.');
    return null;
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
    // Evita URLs, caminhos, nomes de classes...
    if (s.contains('.') || s.contains('/') || s.contains('\\')) return false;
    if (s.length < 16) return false;
    // Precisa ter pelo menos alguns números e letras misturados
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
