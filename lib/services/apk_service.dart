import 'dart:async';
import 'dart:io';
import 'dart:typed_data';
import 'package:archive/archive.dart';
import 'package:path/path.dart' as p;

/// Serviço responsável por descompilar e extrair APKs
class ApkService {
  /// Retorna logs em tempo real via callback
  final void Function(String message) onLog;

  ApkService({required this.onLog});

  // ─────────────────────────────────────────────────────────────────
  // Descompilação via apktool (requer Java no PATH)
  // ─────────────────────────────────────────────────────────────────

  /// Tenta descompilar com apktool.jar.
  /// [apktoolPath] = caminho completo para o apktool.jar
  Future<bool> decompileWithApktool({
    required String apkPath,
    required String outputDir,
    required String apktoolJarPath,
  }) async {
    final jar = File(apktoolJarPath);
    if (!jar.existsSync()) {
      onLog('❌ apktool.jar não encontrado em: $apktoolJarPath');
      return false;
    }

    onLog('📦 Descompilando com apktool...');
    onLog('⏳ Isso pode levar alguns minutos...');

    try {
      final out = Directory(outputDir);
      if (out.existsSync()) {
        out.deleteSync(recursive: true);
      }

      final result = await Process.run(
        'java',
        ['-jar', apktoolJarPath, 'd', apkPath, '-o', outputDir, '-f'],
        runInShell: true,
      ).timeout(const Duration(minutes: 8));

      if (result.exitCode == 0) {
        onLog('✅ APK descompilado com sucesso!');
        return true;
      } else {
        onLog('❌ Erro apktool (code ${result.exitCode}):');
        onLog(result.stderr.toString().trim());
        return false;
      }
    } on TimeoutException {
      onLog('❌ Timeout: descompilação demorou demais (>8 min)');
      return false;
    } on ProcessException catch (e) {
      onLog('❌ Java não encontrado no PATH: ${e.message}');
      onLog('   Instale Java e adicione ao PATH, ou use extração direta.');
      return false;
    } catch (e) {
      onLog('❌ Erro inesperado: $e');
      return false;
    }
  }

  // ─────────────────────────────────────────────────────────────────
  // Extração direta via ZIP (fallback sem Java)
  // APK = ZIP, então podemos extrair assets sem apktool
  // ─────────────────────────────────────────────────────────────────

  /// Extrai o APK diretamente (sem gerar .smali).
  /// Útil para chegar aos assets mesmo sem Java instalado.
  Future<bool> extractApkDirect({
    required String apkPath,
    required String outputDir,
  }) async {
    onLog('📂 Extraindo APK diretamente (sem apktool)...');
    try {
      final bytes = File(apkPath).readAsBytesSync();
      final archive = ZipDecoder().decodeBytes(bytes);

      final outDir = Directory(outputDir);
      outDir.createSync(recursive: true);

      int extracted = 0;
      for (final file in archive) {
        final filePath = p.join(outputDir, file.name);
        if (file.isFile) {
          final outFile = File(filePath);
          outFile.createSync(recursive: true);
          outFile.writeAsBytesSync(file.content as Uint8List);
          extracted++;
        } else {
          Directory(filePath).createSync(recursive: true);
        }
      }

      onLog('✅ APK extraído: $extracted arquivos');
      return true;
    } catch (e) {
      onLog('❌ Erro ao extrair APK: $e');
      return false;
    }
  }

  // ─────────────────────────────────────────────────────────────────
  // Localiza o apktool.jar automaticamente
  // ─────────────────────────────────────────────────────────────────

  /// Procura o apktool.jar em locais comuns
  static Future<String?> findApktool() async {
    final candidates = [
      // Mesmo diretório do executável
      p.join(
        p.dirname(Platform.resolvedExecutable),
        'apktool.jar',
      ),
      // Downloads do Android (Termux)
      if (Platform.isAndroid) '/sdcard/Download/apktool.jar',
      if (Platform.isAndroid) '/storage/emulated/0/Download/apktool.jar',
      // Windows
      if (Platform.isWindows) r'C:\tools\apktool\apktool.jar',
      if (Platform.isWindows)
        p.join(
          Platform.environment['USERPROFILE'] ?? '',
          'Downloads',
          'apktool.jar',
        ),
      // macOS / Linux
      if (!Platform.isWindows && !Platform.isAndroid)
        p.join(
          Platform.environment['HOME'] ?? '',
          'Downloads',
          'apktool.jar',
        ),
    ];

    for (final c in candidates) {
      if (File(c).existsSync()) return c;
    }
    return null;
  }

  /// Verifica se Java está no PATH
  static Future<bool> javaAvailable() async {
    try {
      final r = await Process.run('java', ['-version'], runInShell: true);
      return r.exitCode == 0;
    } catch (_) {
      return false;
    }
  }
}
