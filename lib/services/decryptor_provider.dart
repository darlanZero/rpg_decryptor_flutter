import 'dart:io';
import 'package:flutter/material.dart';
import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../models/decryption_info.dart';
import 'apk_service.dart';
import 'analyzer_service.dart';
import 'decryptor_service.dart';

/// Provider central que gerencia o estado completo da decriptação
class DecryptorProvider extends ChangeNotifier {
  // ─── Estado ───────────────────────────────────────────────────────
  String? apkPath;
  String? apktoolJarPath;
  String outputFolder = '';
  bool useDirectExtraction = false; // fallback sem Java

  /// Caminho absoluto do binário java.
  /// Vazio = usa 'java' do PATH do sistema.
  /// No Termux: /data/data/com.termux/files/usr/bin/java
  String javaPath = '';

  ProcessStep currentStep = ProcessStep.idle;
  double progress = 0.0;
  int filesDecrypted = 0;
  int filesTotal = 0;

  EncryptionInfo? encryptionInfo;
  DecryptionResult? lastResult;

  // Chave manual (caso análise automática falhe)
  String manualSecretKey = '';
  String manualEncType = 'AES-CBC';

  final List<String> _logs = [];
  List<String> get logs => List.unmodifiable(_logs);

  bool get isRunning =>
      currentStep != ProcessStep.idle &&
      currentStep != ProcessStep.done &&
      currentStep != ProcessStep.error;

  // ─── Init ─────────────────────────────────────────────────────────
  DecryptorProvider() {
    _loadPreferences();
  }

  Future<void> _loadPreferences() async {
    final prefs = await SharedPreferences.getInstance();
    apktoolJarPath = prefs.getString('apktool_path');
    outputFolder = prefs.getString('output_folder') ?? '';
    javaPath = prefs.getString('java_path') ?? '';
    useDirectExtraction = prefs.getBool('use_direct_extraction') ?? false;
    notifyListeners();
  }

  Future<void> savePreferences() async {
    final prefs = await SharedPreferences.getInstance();
    if (apktoolJarPath != null) {
      await prefs.setString('apktool_path', apktoolJarPath!);
    }
    if (outputFolder.isNotEmpty) {
      await prefs.setString('output_folder', outputFolder);
    }
    await prefs.setString('java_path', javaPath);
    await prefs.setBool('use_direct_extraction', useDirectExtraction);
  }

  // ─── Controle de Logs ─────────────────────────────────────────────
  void _log(String message) {
    _logs.add('[${_timestamp()}] $message');
    notifyListeners();
  }

  String _timestamp() {
    final now = DateTime.now();
    return '${now.hour.toString().padLeft(2, '0')}:'
        '${now.minute.toString().padLeft(2, '0')}:'
        '${now.second.toString().padLeft(2, '0')}';
  }

  void clearLogs() {
    _logs.clear();
    notifyListeners();
  }

  // ─── Setters ─────────────────────────────────────────────────────
  void setApkPath(String path) {
    apkPath = path;
    _log('📱 APK selecionado: ${p.basename(path)}');
    notifyListeners();
  }

  void setApktoolPath(String path) {
    apktoolJarPath = path;
    savePreferences();
    notifyListeners();
  }

  void setOutputFolder(String path) {
    outputFolder = path;
    savePreferences();
    notifyListeners();
  }

  void setJavaPath(String path) {
    javaPath = path.trim();
    savePreferences();
    notifyListeners();
  }

  // ─── Processo Principal ───────────────────────────────────────────
  Future<void> runFullProcess() async {
    if (apkPath == null || apkPath!.isEmpty) {
      _log('❌ Selecione um APK antes de iniciar.');
      return;
    }

    _logs.clear();
    encryptionInfo = null;
    lastResult = null;
    progress = 0;
    filesDecrypted = 0;
    filesTotal = 0;
    notifyListeners();

    try {
      // ── Passo 1: Determinar pasta de trabalho ────────────────────
      final workDir = await _resolveWorkDir();
      _log('📁 Dir de trabalho: $workDir');

      // ── Passo 2: Descompilar / Extrair ───────────────────────────
      _setStep(ProcessStep.decompiling, 0.1);

      final decompiledDir = p.join(workDir, 'decompiled');
      bool decompiled = false;

      if (!useDirectExtraction && apktoolJarPath != null) {
        final apkSvc = ApkService(onLog: _log);
        decompiled = await apkSvc.decompileWithApktool(
          apkPath: apkPath!,
          outputDir: decompiledDir,
          apktoolJarPath: apktoolJarPath!,
          javaExecutable: javaPath.isEmpty ? 'java' : javaPath,
        );
      }

      if (!decompiled) {
        _log('⚠️  Usando extração direta (sem apktool)...');
        final apkSvc = ApkService(onLog: _log);
        decompiled = await apkSvc.extractApkDirect(
          apkPath: apkPath!,
          outputDir: decompiledDir,
        );
      }

      if (!decompiled) {
        _log('❌ Falha na extração do APK.');
        _setStep(ProcessStep.error, 0);
        return;
      }

      _setStep(ProcessStep.decompiling, 0.3);

      // ── Passo 3: Analisar criptografia ───────────────────────────
      _setStep(ProcessStep.analyzing, 0.4);

      final analyzerSvc = AnalyzerService(onLog: _log);
      EncryptionInfo? info = await analyzerSvc.analyze(decompiledDir);

      // Usa chave manual se análise automática falhar
      if (info == null) {
        if (manualSecretKey.isEmpty) {
          _log('❌ Chave não encontrada. Insira manualmente e tente novamente.');
          _setStep(ProcessStep.error, 0);
          return;
        }
        _log('🔑 Usando chave manual inserida pelo usuário.');
        info = EncryptionInfo(
          secretKey: manualSecretKey,
          encryptionType: manualEncType,
          sourceFile: 'manual',
        );
      }

      // ── Guardrail: força AES para arquivos .json.enc ─────────────
      // XOR é usado exclusivamente para imagens/áudio no RPG Maker MV/MZ
      // padrão. Arquivos .json.enc são cifrados com AES pelo runtime Android.
      // Se o analisador retornou XOR mas existem .json.enc, sobrescreve para AES-CBC.
      if (info.encryptionType.toUpperCase() == 'XOR') {
        final hasJsonEnc = _hasJsonEncFiles(decompiledDir);
        if (hasJsonEnc) {
          _log('⚠️  Tipo XOR detectado, mas há arquivos .json.enc (AES).');
          _log('   → Sobrescrevendo para AES-CBC (correto para .json.enc).');
          info = EncryptionInfo(
            secretKey: info.secretKey,
            encryptionType: 'AES-CBC',
            sourceFile: info.sourceFile,
          );
        }
      }

      encryptionInfo = info;
      _setStep(ProcessStep.analyzing, 0.55);

      // ── Passo 4: Localizar assets do APK ─────────────────────────
      final assetsRoot = DecryptorService.findAssetsRoot(decompiledDir);
      final hasEnc = DecryptorService.hasEncFiles(assetsRoot);

      if (!hasEnc) {
        _log('⚠️  Nenhum arquivo .enc encontrado.');
        _log('   Exportando todos os assets sem decriptação...');
      } else {
        _log('📂 Assets raiz: $assetsRoot');
      }

      // ── Passo 5: Exportar tudo + decriptar .enc ───────────────────
      _setStep(ProcessStep.decrypting, 0.6);

      // Pasta de saída
      final outDir = outputFolder.isNotEmpty
          ? outputFolder
          : p.join(workDir, 'decrypted');

      final decryptorSvc = DecryptorService(onLog: _log);
      filesDecrypted = await decryptorSvc.exportAllAssets(
        assetsRoot: assetsRoot,
        outputFolder: outDir,
        secretKey: info.secretKey,
        encType: info.encryptionType,
        onProgress: (current, total) {
          filesTotal = total;
          progress = 0.6 + (current / total) * 0.4;
          notifyListeners();
        },
      );

      // ── Resultado ────────────────────────────────────────────────
      lastResult = DecryptionResult(
        apkPath: apkPath!,
        encryptionInfo: info,
        filesDecrypted: filesDecrypted,
        filesTotal: filesTotal,
        outputFolder: outDir,
      );

      // Considera sucesso se decriptou algum .enc OU se não havia .enc
      // mas exportou arquivos normais (verificamos pela pasta de saída)
      final outDirFiles = Directory(outDir).existsSync()
          ? Directory(outDir).listSync(recursive: true).whereType<File>().length
          : 0;

      if (outDirFiles > 0) {
        _log('');
        _log('🎉 CONCLUÍDO! $filesDecrypted .enc decriptado(s) + '
             '${outDirFiles - filesDecrypted} arquivo(s) copiado(s)');
        _log('📁 Saída: $outDir');
        _setStep(ProcessStep.done, 1.0);
      } else {
        _log('⚠️  Nenhum arquivo exportado. Verifique permissões ou a chave.');
        _setStep(ProcessStep.error, 0);
      }
    } catch (e, stack) {
      _log('❌ Erro fatal: $e');
      debugPrint(stack.toString());
      _setStep(ProcessStep.error, 0);
    }
  }

  void _setStep(ProcessStep step, double prog) {
    currentStep = step;
    progress = prog;
    notifyListeners();
  }

  void reset() {
    currentStep = ProcessStep.idle;
    progress = 0;
    encryptionInfo = null;
    lastResult = null;
    filesDecrypted = 0;
    filesTotal = 0;
    _logs.clear();
    notifyListeners();
  }

  // ─── Helpers ─────────────────────────────────────────────────────

  /// Verifica se há arquivos .json.enc em qualquer subdirectório de [dir]
  bool _hasJsonEncFiles(String dir) {
    try {
      return Directory(dir)
          .listSync(recursive: true)
          .whereType<File>()
          .any((f) => f.path.endsWith('.json.enc'));
    } catch (_) {
      return false;
    }
  }

  Future<String> _resolveWorkDir() async {
    if (Platform.isAndroid) {
      // Tenta usar storage externo no Android
      final dirs = await getExternalStorageDirectories();
      if (dirs != null && dirs.isNotEmpty) {
        final work = p.join(dirs.first.path, 'apk-analysis');
        Directory(work).createSync(recursive: true);
        return work;
      }
    }

    final temp = await getTemporaryDirectory();
    final work = p.join(temp.path, 'apk-analysis');
    Directory(work).createSync(recursive: true);
    return work;
  }
}
