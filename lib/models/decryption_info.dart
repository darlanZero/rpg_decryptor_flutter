/// Resultado da análise de criptografia
class EncryptionInfo {
  final String secretKey;
  final String encryptionType;
  final String sourceFile;

  const EncryptionInfo({
    required this.secretKey,
    required this.encryptionType,
    required this.sourceFile,
  });

  Map<String, dynamic> toJson() => {
        'secretKey': secretKey,
        'encryptionType': encryptionType,
        'sourceFile': sourceFile,
      };
}

/// Resultado completo do processo de decriptação
class DecryptionResult {
  final String apkPath;
  final EncryptionInfo? encryptionInfo;
  final int filesDecrypted;
  final int filesTotal;
  final String outputFolder;
  final List<String> errors;

  const DecryptionResult({
    required this.apkPath,
    this.encryptionInfo,
    required this.filesDecrypted,
    required this.filesTotal,
    required this.outputFolder,
    this.errors = const [],
  });

  bool get success => filesDecrypted > 0;
}

/// Etapas do processo
enum ProcessStep {
  idle,
  decompiling,
  analyzing,
  decrypting,
  done,
  error,
}

extension ProcessStepLabel on ProcessStep {
  String get label {
    switch (this) {
      case ProcessStep.idle:
        return 'Aguardando';
      case ProcessStep.decompiling:
        return 'Descompilando APK...';
      case ProcessStep.analyzing:
        return 'Analisando Criptografia...';
      case ProcessStep.decrypting:
        return 'Descriptografando Arquivos...';
      case ProcessStep.done:
        return 'Concluído!';
      case ProcessStep.error:
        return 'Erro';
    }
  }
}
