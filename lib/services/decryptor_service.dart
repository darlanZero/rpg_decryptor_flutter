import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:encrypt/encrypt.dart' as enc;
import 'package:path/path.dart' as p;

/// Descriptografa arquivos .enc usando AES-CBC, AES-ECB ou XOR
class DecryptorService {
  final void Function(String message) onLog;

  DecryptorService({required this.onLog});

  // ─────────────────────────────────────────────────────────────────
  // Derivação de chave
  // ─────────────────────────────────────────────────────────────────

  /// Gera bytes da chave AES (SHA-256 do segredo = 32 bytes)
  Uint8List _deriveAesKey(String secretKey) {
    final digest = sha256.convert(utf8.encode(secretKey));
    return Uint8List.fromList(digest.bytes);
  }

  // ─────────────────────────────────────────────────────────────────
  // Descriptografia de arquivo único
  // ─────────────────────────────────────────────────────────────────

  Uint8List? decryptFile(Uint8List data, String secretKey, String encType) {
    switch (encType.toUpperCase()) {
      case 'AES-CBC':
      case 'AES':
        return _decryptAesCbc(data, _deriveAesKey(secretKey));
      case 'AES-ECB':
        return _decryptAesEcb(data, _deriveAesKey(secretKey));
      case 'XOR':
        return _decryptXor(data, Uint8List.fromList(utf8.encode(secretKey)));
      default:
        // Tenta AES-CBC como padrão
        return _decryptAesCbc(data, _deriveAesKey(secretKey));
    }
  }

  Uint8List? _decryptAesCbc(Uint8List data, Uint8List keyBytes) {
    if (data.length < 16) return null;
    try {
      final iv = enc.IV(Uint8List.fromList(data.sublist(0, 16)));
      final key = enc.Key(keyBytes);
      final encrypter = enc.Encrypter(
        enc.AES(key, mode: enc.AESMode.cbc, padding: 'PKCS7'),
      );
      final ciphertext = enc.Encrypted(
        Uint8List.fromList(data.sublist(16)),
      );
      final decrypted = encrypter.decryptBytes(ciphertext, iv: iv);
      return Uint8List.fromList(decrypted);
    } catch (_) {
      // Tenta sem padding (alguns jogos não usam padding PKCS7)
      try {
        final iv = enc.IV(Uint8List.fromList(data.sublist(0, 16)));
        final key = enc.Key(keyBytes);
        final encrypter = enc.Encrypter(
          enc.AES(key, mode: enc.AESMode.cbc, padding: null),
        );
        final ciphertext = enc.Encrypted(
          Uint8List.fromList(data.sublist(16)),
        );
        final decrypted = encrypter.decryptBytes(ciphertext, iv: iv);
        return Uint8List.fromList(decrypted);
      } catch (_) {
        return null;
      }
    }
  }

  Uint8List? _decryptAesEcb(Uint8List data, Uint8List keyBytes) {
    try {
      final key = enc.Key(keyBytes);
      final encrypter = enc.Encrypter(
        enc.AES(key, mode: enc.AESMode.ecb, padding: 'PKCS7'),
      );
      final ciphertext = enc.Encrypted(data);
      final decrypted = encrypter.decryptBytes(ciphertext, iv: enc.IV.allZerosOfLength(16));
      return Uint8List.fromList(decrypted);
    } catch (_) {
      return null;
    }
  }

  Uint8List _decryptXor(Uint8List data, Uint8List key) {
    final result = Uint8List(data.length);
    for (int i = 0; i < data.length; i++) {
      result[i] = data[i] ^ key[i % key.length];
    }
    return result;
  }

  // ─────────────────────────────────────────────────────────────────
  // Descriptografia em lote (pasta inteira)
  // ─────────────────────────────────────────────────────────────────

  Future<int> decryptFolder({
    required String inputFolder,
    required String outputFolder,
    required String secretKey,
    required String encType,
    String extension = '.enc',
    void Function(int current, int total)? onProgress,
  }) async {
    final inputDir = Directory(inputFolder);
    if (!inputDir.existsSync()) {
      onLog('❌ Pasta não encontrada: $inputFolder');
      return 0;
    }

    final outDir = Directory(outputFolder);
    outDir.createSync(recursive: true);

    // Lista todos os .enc (recursivo)
    final encFiles = inputDir
        .listSync(recursive: true)
        .whereType<File>()
        .where((f) => f.path.endsWith(extension))
        .toList();

    if (encFiles.isEmpty) {
      onLog('⚠️  Nenhum arquivo $extension encontrado em: $inputFolder');
      return 0;
    }

    onLog('📋 ${encFiles.length} arquivo(s) para descriptografar');
    onLog('${'─' * 40}');

    int success = 0;

    for (int i = 0; i < encFiles.length; i++) {
      final file = encFiles[i];
      final relativePath = p.relative(file.path, from: inputFolder);

      // Monta caminho de saída preservando sub-pastas
      final outPath = p.join(
        outputFolder,
        relativePath.replaceAll(RegExp(r'\.enc$'), ''),
      );

      // Cria sub-diretórios necessários
      Directory(p.dirname(outPath)).createSync(recursive: true);

      final data = file.readAsBytesSync();
      final decrypted = decryptFile(data, secretKey, encType);

      if (decrypted != null) {
        File(outPath).writeAsBytesSync(decrypted);
        success++;
        onLog('[${i + 1}/${encFiles.length}] ✅ ${p.basename(file.path)}');
      } else {
        onLog('[${i + 1}/${encFiles.length}] ❌ ${p.basename(file.path)}');
      }

      onProgress?.call(i + 1, encFiles.length);
    }

    onLog('${'─' * 40}');
    onLog('🎉 Resultado: $success/${encFiles.length} descriptografados');

    return success;
  }

  // ─────────────────────────────────────────────────────────────────
  // Procura a pasta de assets criptografados no APK descompilado
  // ─────────────────────────────────────────────────────────────────

  static String? findEncFolder(String decompiledDir) {
    final candidates = [
      p.join(decompiledDir, 'assets', 'data'),
      p.join(decompiledDir, 'assets'),
      decompiledDir,
    ];

    for (final c in candidates) {
      final dir = Directory(c);
      if (!dir.existsSync()) continue;

      final hasEnc = dir
          .listSync(recursive: true)
          .whereType<File>()
          .any((f) => f.path.endsWith('.enc'));

      if (hasEnc) return c;
    }
    return null;
  }
}
