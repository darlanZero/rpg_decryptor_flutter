import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:encrypt/encrypt.dart' as enc;
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
  // Chaves placeholder / teste conhecidas — nunca são chaves reais
  // "0123456789ABCDEF" é o valor padrão no runtime do RPG Maker Android
  // ─────────────────────────────────────────────────────────────────
  static const _knownPlaceholders = {
    // RPG Maker Android runtime placeholder (o mais comum)
    '0123456789ABCDEF',
    '0123456789abcdef',
    '0123456789ABCDEF0123456789ABCDEF', // versão 32-char
    '0123456789abcdef0123456789abcdef',
    // Padrões sequenciais / triviais
    '1234567890123456',
    '1234567890ABCDEF',
    '1234567890abcdef',
    'ABCDEFABCDEFABCD',
    'abcdefabcdefabcd',
    'FEDCBA9876543210',
    'fedcba9876543210',
    // Repetições de um único byte
    '0000000000000000',
    'AAAAAAAAAAAAAAAA',
    'aaaaaaaaaaaaaaaa',
    'FFFFFFFFFFFFFFFF',
    'ffffffffffffffff',
    // Strings de teste genéricas
    'encryptionkey123',
    'defaultsecretkey',
    'testkey123456789',
    'secretkey1234567',
    'PASSWORD12345678',
    'password12345678',
    'RPGMakerSecretKey',
  };

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

    // Antes de escanear, analisa um arquivo .enc para entender o algoritmo real
    await _probeEncFile(dir);

    // Método 2: varredura de strings em arquivos .dex
    final dexResult = await _scanDexFiles(dir);
    if (dexResult != null) return dexResult;

    // Método 3: varredura de bibliotecas nativas .so (C/C++)
    // Chaves frequentemente ficam em código nativo para dificultar reverse engineering
    final soResult = await _scanSoLibraries(dir);
    if (soResult != null) return soResult;

    onLog('❌ Chave não encontrada automaticamente.');
    onLog('💡 Insira a chave manualmente na seção "Chave Manual".');
    return null;
  }

  // ─────────────────────────────────────────────────────────────────
  // Probe de .enc — detecta o algoritmo real pelos primeiros bytes
  // ─────────────────────────────────────────────────────────────────

  Future<void> _probeEncFile(String dir) async {
    // Encontra o primeiro .enc disponível para análise
    File? sample;
    try {
      await for (final entity in Directory(dir).list(recursive: true)) {
        if (entity is File && entity.path.endsWith('.enc')) {
          sample = entity;
          break;
        }
      }
    } catch (_) {}

    if (sample == null) return;

    try {
      final bytes = sample.readAsBytesSync();
      if (bytes.length < 32) return;

      onLog('🔎 Análise do formato .enc: ${p.basename(sample.path)}');
      onLog('   Tamanho: ${bytes.length} bytes');

      // ── Detecção de magic header RPG Maker MV ──────────────────
      // Header: 52 50 47 4D 56 00 00 00 00 03 01 00 00 00 00 00
      final rpgMvMagic = [0x52,0x50,0x47,0x4D,0x56,0x00,0x00,0x00,0x00,0x03,0x01,0x00,0x00,0x00,0x00,0x00];
      final hasRpgMvHeader = bytes.length >= 16 &&
          List.generate(16, (i) => bytes[i]).toString() == rpgMvMagic.toString();

      if (hasRpgMvHeader) {
        onLog('   📌 Header RPG Maker MV detectado (16 bytes)');
        onLog('   → Dados encriptados começam no offset 16');
        onLog('   → Algoritmo: XOR com chave derivada de encryptionKey');
        return;
      }

      // ── Análise de entropia e estrutura ────────────────────────
      final first16 = bytes.sublist(0, 16);
      final entropy = _estimateEntropy(first16);
      onLog('   Entropia primeiros 16 bytes: ${entropy.toStringAsFixed(2)}/8.00');

      // AES-CBC: primeiro bloco é o IV (alta entropia, aleatório)
      // XOR: distribuição mais uniforme, primeiro byte XOR chave[0] = '{'
      if (entropy > 7.0) {
        onLog('   📌 Alta entropia → provável IV (AES-CBC) ou dados altamente aleatórios');
      } else if (entropy < 4.0) {
        onLog('   📌 Baixa entropia → pode ser XOR ou dados comprimidos não-criptografados');
      }

      // Múltiplo de 16: sugere cipher de bloco (AES)
      if (bytes.length % 16 == 0) {
        onLog('   📌 Tamanho múltiplo de 16 → compatível com AES (bloco 128-bit)');
      } else {
        onLog('   📌 Tamanho não é múltiplo de 16 → mais compatível com XOR/stream cipher');
      }

      // Primeiros bytes em hex para diagnóstico manual
      final hexDump = first16.map((b) => b.toRadixString(16).padLeft(2, '0')).join(' ');
      onLog('   Hex [0..15]: $hexDump');

    } catch (e) {
      onLog('   ⚠️  Erro na análise do .enc: $e');
    }
  }

  /// Entropia de Shannon em bits por símbolo (0–8).
  ///
  /// Fórmula correta: H = -Σ p(i) * log2(p(i))
  /// onde log2(x) = ln(x) / ln(2) = ln(x) * 1.4426950408889634
  ///
  /// Interpretação:
  ///   0   → sem variância (todos bytes iguais)
  ///   4–5 → entropia moderada (XOR com chave simples)
  ///   7–8 → alta entropia (AES ou dados verdadeiramente aleatórios)
  double _estimateEntropy(List<int> bytes) {
    if (bytes.isEmpty) return 0.0;
    final freq = <int, int>{};
    for (final b in bytes) {
      freq[b] = (freq[b] ?? 0) + 1;
    }
    double entropy = 0.0;
    final n = bytes.length;
    for (final count in freq.values) {
      if (count == 0) continue;
      final prob = count / n;
      entropy -= prob * (log(prob) * 1.4426950408889634); // log2(p)
    }
    return entropy.clamp(0.0, 8.0);
  }

  // ─────────────────────────────────────────────────────────────────
  // Método 3 — Bibliotecas nativas .so (ELF ARM)
  //
  // Chaves de criptografia são frequentemente hardcoded em código C/C++
  // compilado para ARM64, visível como strings ASCII na seção .rodata do ELF.
  // Técnica: busca sequências de ASCII imprimível ≥ 16 chars entre null bytes
  // (equivalente ao comando Unix `strings`).
  // ─────────────────────────────────────────────────────────────────

  Future<EncryptionInfo?> _scanSoLibraries(String dir) async {
    onLog('🔬 Varrendo bibliotecas nativas .so...');

    // Prioridades de arquitetura (ARM64 é o padrão moderno)
    final archPaths = [
      p.join(dir, 'lib', 'arm64-v8a'),
      p.join(dir, 'lib', 'armeabi-v7a'),
      p.join(dir, 'lib', 'x86_64'),
    ];

    final soFiles = <File>[];
    for (final archPath in archPaths) {
      final archDir = Directory(archPath);
      if (!archDir.existsSync()) continue;
      try {
        final found = archDir.listSync(recursive: true)
            .whereType<File>()
            .where((f) => f.path.endsWith('.so'))
            .toList();
        soFiles.addAll(found);
        if (soFiles.isNotEmpty) break; // usa a primeira arquitetura encontrada
      } catch (_) {}
    }

    // Fallback: busca recursiva se não encontrou nas pastas lib/
    if (soFiles.isEmpty) {
      try {
        await for (final entity in Directory(dir).list(recursive: true)) {
          if (entity is File && entity.path.endsWith('.so')) {
            soFiles.add(entity);
            if (soFiles.length >= 10) break;
          }
        }
      } catch (_) {}
    }

    if (soFiles.isEmpty) {
      onLog('   ⚠️  Nenhuma biblioteca .so encontrada.');
      return null;
    }

    onLog('   ${soFiles.length} biblioteca(s) .so encontrada(s)');

    for (final soFile in soFiles) {
      final result = await _extractKeyFromSo(soFile, dir);
      if (result != null) return result;
    }

    return null;
  }

  Future<EncryptionInfo?> _extractKeyFromSo(File soFile, String dir) async {
    try {
      final stat = soFile.statSync();
      // Lê até 30MB (libgame.so pode ser grande)
      final maxBytes = min(stat.size, 30 * 1024 * 1024);
      final raf = soFile.openSync();
      final bytes = raf.readSync(maxBytes);
      raf.closeSync();

      // Extrai strings ASCII da forma `strings`: sequências de printable ASCII
      // separadas por bytes não-printáveis (null bytes, control chars, etc.)
      final keyCandidates = <String>[];
      final buf = StringBuffer();
      String? lastEncType;

      for (int i = 0; i <= bytes.length; i++) {
        final b = i < bytes.length ? bytes[i] : 0;
        final isPrintable = b >= 0x20 && b <= 0x7E;

        if (isPrintable) {
          buf.write(String.fromCharCode(b));
        } else {
          if (buf.length >= 16) {
            final s = buf.toString();

            // Detecta strings de tipo de cifra (ajuda a definir o algoritmo)
            if (s.contains('AES/CBC')) lastEncType = 'AES-CBC';
            if (s.contains('AES/ECB')) lastEncType = 'AES-ECB';

            // Filtra candidatos a chave com o mesmo critério do DexParser
            if (_isSoKeyCandidate(s)) {
              keyCandidates.add(s);
            }
          }
          buf.clear();
        }
      }

      if (keyCandidates.isEmpty) return null;

      // Ordena por score mais plausível
      keyCandidates.sort((a, b) => _soKeyScore(b).compareTo(_soKeyScore(a)));

      // Filtra placeholders conhecidos
      final realCandidates = keyCandidates.where((k) => !_isPlaceholderKey(k)).toList();

      if (realCandidates.isEmpty) {
        onLog('   ⚠️  ${p.basename(soFile.path)}: somente placeholders encontrados');
        return null;
      }

      onLog('   🔬 ${realCandidates.length} candidato(s) .so após filtro de placeholders');
      if (realCandidates.length > 1) {
        final alts = realCandidates.skip(1).take(3)
            .map((s) => s.length > 12 ? '${s.substring(0, 12)}...' : s)
            .join(', ');
        onLog('   💡 Alternativas: $alts');
      }

      // Valida cada candidato contra .json.enc real
      final maxToTry = min(realCandidates.length, 5);
      for (int i = 0; i < maxToTry; i++) {
        final candidate = realCandidates[i];
        final shortKey = candidate.length > 20
            ? '${candidate.substring(0, 20)}...'
            : candidate;
        onLog('   🔎 Candidato .so ${i + 1}/$maxToTry: $shortKey');

        final confirmedType = await _validateKeyAgainstJsonEnc(dir, candidate);
        if (confirmedType != null) {
          onLog('🔑 Chave confirmada em ${p.basename(soFile.path)}: $shortKey');
          onLog('🔒 Tipo: $confirmedType (validado via decriptação AES)');
          return EncryptionInfo(
            secretKey: candidate,
            encryptionType: confirmedType,
            sourceFile: p.basename(soFile.path),
          );
        }
      }

      onLog('   ⚠️  Nenhum candidato .so produziu JSON válido.');
      return null;
    } catch (e) {
      onLog('   ⚠️  Erro ao ler ${p.basename(soFile.path)}: $e');
    }
    return null;
  }

  /// Critério para candidatos a chave encontrados em .so (mais permissivo que DEX
  /// pois strings em .so podem ter contexto diferente)
  bool _isSoKeyCandidate(String s) {
    final len = s.length;
    if (len < 16 || len > 64) return false;

    // Rejeita qualquer char fora do range printável seguro
    for (int i = 0; i < len; i++) {
      final c = s.codeUnitAt(i);
      if (c < 0x21 || c > 0x7E) return false;
    }

    // Hex puro de tamanho adequado para AES
    final isHex = RegExp(r'^[0-9a-fA-F]+$').hasMatch(s);
    if (isHex && (len == 32 || len == 48 || len == 64)) return true;
    if (isHex && len >= 16) return true;

    // Rejeita paths, símbolos C/C++, funções
    if (s.contains('.') || s.contains('/') || s.contains('\\')) return false;
    if (s.contains('<') || s.contains('>') || s.contains('(')) return false;
    if (s.contains(':') || s.contains(';') || s.contains(',')) return false;
    if (s.contains('_')) return false; // nomes de função C (ex: Java_com_...)
    if (s.contains(' ')) return false;

    // Alfanumérico misto com dígitos
    final hasDigit = s.contains(RegExp(r'\d'));
    final hasLetter = s.contains(RegExp(r'[A-Za-z]'));
    if (!hasDigit || !hasLetter) return false;

    if (RegExp(r'^[A-Za-z0-9+/=]+$').hasMatch(s)) return true;

    return false;
  }

  int _soKeyScore(String s) {
    final len = s.length;
    final isHex = RegExp(r'^[0-9a-fA-F]+$').hasMatch(s);
    if (isHex && len == 32) return 100;
    if (isHex && len == 64) return 90;
    if (isHex && len == 48) return 80;
    if (isHex && len >= 16) return 60;
    if (len >= 24) return 40;
    return 20;
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
      final result = await _extractKeyFromDex(dex, dir);
      if (result != null) return result;
    }

    return null;
  }

  /// Usa [DexParser] para extrair strings do formato binário DEX,
  /// filtra chaves placeholder e valida cada candidata contra um .enc real.
  Future<EncryptionInfo?> _extractKeyFromDex(File dexFile, String dir) async {
    try {
      final stat = dexFile.statSync();
      // Lê até 20MB para DEX grandes (classes.dex de jogos pode ser volumoso)
      final maxBytes = min(stat.size, 20 * 1024 * 1024);
      final raf = dexFile.openSync();
      final bytes = raf.readSync(maxBytes);
      raf.closeSync();

      final parser = DexParser(bytes);

      if (!parser.isValidDex) return null;

      // Verifica se este DEX tem referências a crypto antes de varrer tudo
      final hasCrypto = parser.hasCryptoReferences();
      if (!hasCrypto) return null;

      final encTypeHint = parser.detectEncryptionType();
      onLog('   📂 ${p.basename(dexFile.path)}: DEX v${parser.version}, '
            'refs crypto → $encTypeHint');

      // Extrai candidatos ordenados por confiança (hex 32/48/64 chars primeiro)
      final keyCandidates = parser.extractKeysCandidates();

      if (keyCandidates.isEmpty) {
        onLog('   ⚠️  Nenhum candidato a chave válido nas strings do DEX.');
        return null;
      }

      // ── Filtra chaves placeholder / teste conhecidas ──────────────
      final realCandidates = keyCandidates.where((k) => !_isPlaceholderKey(k)).toList();

      if (realCandidates.isEmpty) {
        final placeholders = keyCandidates.take(3).map((k) =>
            k.length > 16 ? '${k.substring(0, 16)}...' : k).join(', ');
        onLog('   ⚠️  Todos os candidatos são placeholders: $placeholders');
        onLog('   → Chave real provavelmente está em biblioteca nativa .so');
        return null;
      }

      onLog('   🔎 ${realCandidates.length} candidato(s) após filtro de placeholders');

      // ── Valida cada candidato contra um .json.enc real ───────────
      // Testa no máximo os 5 melhores candidatos (ordenados por score)
      final maxToTry = min(realCandidates.length, 5);
      for (int i = 0; i < maxToTry; i++) {
        final candidate = realCandidates[i];
        final shortKey = candidate.length > 20
            ? '${candidate.substring(0, 20)}...'
            : candidate;
        onLog('   🔎 Candidato ${i + 1}/$maxToTry: $shortKey');

        final confirmedType = await _validateKeyAgainstJsonEnc(dir, candidate);
        if (confirmedType != null) {
          onLog('🔑 Chave confirmada em ${p.basename(dexFile.path)}: $shortKey');
          onLog('🔒 Tipo: $confirmedType (validado via decriptação AES)');
          return EncryptionInfo(
            secretKey: candidate,
            encryptionType: confirmedType,
            sourceFile: p.basename(dexFile.path),
          );
        }
      }

      onLog('   ⚠️  Nenhum candidato DEX produziu JSON válido.');
      return null;
    } catch (e) {
      onLog('   ⚠️  Erro ao parsear ${p.basename(dexFile.path)}: $e');
    }
    return null;
  }

  // ─────────────────────────────────────────────────────────────────
  // Validação de chave — tenta decriptar um .json.enc real e
  // verifica se o resultado é JSON válido.
  //
  // Por que isso é necessário:
  //   • O DEX do runtime RPG Maker Android contém "0123456789ABCDEF"
  //     como placeholder — nunca é a chave real do jogo.
  //   • Arquivos .json.enc usam AES-CBC ou AES-ECB, NÃO XOR.
  //     XOR é exclusivo das imagens/áudio no formato RPG Maker MV/MZ.
  //   • Precisamos confirmar que a chave realmente decripta um .json.enc
  //     antes de retorná-la como resultado.
  // ─────────────────────────────────────────────────────────────────

  /// Retorna true se a string é uma chave placeholder/teste conhecida.
  bool _isPlaceholderKey(String key) {
    // Verifica contra a lista de placeholders conhecidos (case-insensitive)
    final upper = key.toUpperCase();
    for (final placeholder in _knownPlaceholders) {
      if (upper == placeholder.toUpperCase()) return true;
    }

    // Sequencial hexadecimal ascendente ou descendente
    final lower = key.toLowerCase();
    if (lower.startsWith('01234567') || lower.startsWith('fedcba98')) return true;

    // Todos os caracteres iguais (entropia zero)
    if (key.split('').toSet().length <= 1) return true;

    // Padrão óbvio de repetição (ex: "ABABABABABABABAB")
    if (key.length >= 4) {
      final half = key.substring(0, key.length ~/ 2);
      final doubled = half + half;
      if (doubled == key || doubled.substring(0, key.length) == key) {
        // Só rejeita se a metade também parecer placeholder
        if (half.toLowerCase().startsWith('01234') ||
            half.toLowerCase() == 'abcd' * (half.length ~/ 4)) {
          return true;
        }
      }
    }

    return false;
  }

  /// Valida uma chave candidata tentando decriptar um arquivo .json.enc real.
  ///
  /// Estratégia:
  ///   1. Encontra o menor .json.enc em assets/data/ (ou qualquer .enc)
  ///   2. Tenta AES-CBC (IV = primeiros 16 bytes, cifra = restante)
  ///   3. Tenta AES-ECB (sem IV, cifra = dados completos)
  ///   4. Também tenta a chave hex bruta (sem derivação SHA-256)
  ///   5. Verifica se o resultado começa com '{' ou '[' (JSON válido)
  ///
  /// Retorna o tipo de encriptação confirmado ('AES-CBC' ou 'AES-ECB'),
  /// ou null se a chave não produzir JSON válido com nenhum modo.
  Future<String?> _validateKeyAgainstJsonEnc(String dir, String key) async {
    // Procura o menor .json.enc em assets/data/ para validação
    File? sample;
    int minSize = 999999999;

    try {
      final dataDir = Directory(p.join(dir, 'assets', 'data'));
      if (dataDir.existsSync()) {
        await for (final entity in dataDir.list(recursive: true)) {
          if (entity is File && entity.path.endsWith('.json.enc')) {
            final size = entity.statSync().size;
            // Tamanho mínimo: pelo menos 32 bytes (IV + 1 bloco)
            if (size >= 32 && size < minSize) {
              minSize = size;
              sample = entity;
            }
          }
        }
      }
    } catch (_) {}

    // Fallback: qualquer .enc (exceto os com magic header RPG Maker MV)
    if (sample == null) {
      try {
        await for (final entity in Directory(dir).list(recursive: true)) {
          if (entity is File && entity.path.endsWith('.enc')) {
            final size = entity.statSync().size;
            if (size >= 32 && size < minSize) {
              minSize = size;
              sample = entity;
            }
          }
        }
      } catch (_) {}
    }

    if (sample == null) {
      onLog('   ⚠️  Nenhum .enc disponível para validar a chave');
      return null;
    }

    try {
      final bytes = sample.readAsBytesSync();
      if (bytes.length < 32) return null;

      // Pula arquivos com magic header RPG Maker MV (são XOR, não AES)
      final rpgMvMagic = [0x52, 0x50, 0x47, 0x4D, 0x56];
      bool hasRpgHeader = bytes.length >= 5 &&
          List.generate(5, (i) => bytes[i]).toString() == rpgMvMagic.toString();
      if (hasRpgHeader) {
        onLog('   ⚠️  .enc tem header RPG Maker MV (XOR) — não serve para validar AES');
        return null;
      }

      final sampleName = p.basename(sample.path);
      onLog('   🧪 Validando chave contra: $sampleName (${bytes.length} bytes)');

      final sha256Key = _deriveKeyFromSecret(key);

      // ── Tentativa 1: AES-CBC com SHA-256(key) ────────────────────
      final cbc1 = _tryAesCbc(bytes, sha256Key);
      if (cbc1 != null && _looksLikeJson(cbc1)) {
        onLog('   ✅ AES-CBC (SHA-256) → JSON válido confirmado!');
        return 'AES-CBC';
      }

      // ── Tentativa 2: AES-ECB com SHA-256(key) ────────────────────
      final ecb1 = _tryAesEcb(bytes, sha256Key);
      if (ecb1 != null && _looksLikeJson(ecb1)) {
        onLog('   ✅ AES-ECB (SHA-256) → JSON válido confirmado!');
        return 'AES-ECB';
      }

      // ── Tentativa 3 e 4: chave hex bruta (sem SHA-256) ───────────
      // Alguns APKs usam a chave hex diretamente como bytes AES
      final isHex = RegExp(r'^[0-9a-fA-F]+$').hasMatch(key);
      if (isHex && (key.length == 32 || key.length == 48 || key.length == 64)) {
        final rawKey = _hexToBytes(key);

        final cbc2 = _tryAesCbc(bytes, rawKey);
        if (cbc2 != null && _looksLikeJson(cbc2)) {
          onLog('   ✅ AES-CBC (hex raw) → JSON válido confirmado!');
          return 'AES-CBC';
        }

        final ecb2 = _tryAesEcb(bytes, rawKey);
        if (ecb2 != null && _looksLikeJson(ecb2)) {
          onLog('   ✅ AES-ECB (hex raw) → JSON válido confirmado!');
          return 'AES-ECB';
        }
      }

      // ── Tentativa 5: UTF-8 raw (sem SHA-256, sem hex decode) ─────
      // Chaves alfanuméricas podem ser usadas diretamente com padding
      if (!isHex) {
        final utf8Key = _deriveKeyUtf8Raw(key);
        if (utf8Key != null) {
          final cbc3 = _tryAesCbc(bytes, utf8Key);
          if (cbc3 != null && _looksLikeJson(cbc3)) {
            onLog('   ✅ AES-CBC (UTF-8 raw) → JSON válido confirmado!');
            return 'AES-CBC';
          }
          final ecb3 = _tryAesEcb(bytes, utf8Key);
          if (ecb3 != null && _looksLikeJson(ecb3)) {
            onLog('   ✅ AES-ECB (UTF-8 raw) → JSON válido confirmado!');
            return 'AES-ECB';
          }
        }
      }

      onLog('   ❌ Chave não produziu JSON válido em nenhum modo AES');
      return null;
    } catch (e) {
      onLog('   ⚠️  Erro na validação: $e');
      return null;
    }
  }

  // ─── Derivação de chave ─────────────────────────────────────────

  /// SHA-256(secret) → 32 bytes (AES-256)
  Uint8List _deriveKeyFromSecret(String secret) {
    final digest = sha256.convert(utf8.encode(secret));
    return Uint8List.fromList(digest.bytes);
  }

  /// UTF-8 encode + pad/truncate para 32 bytes (AES-256)
  Uint8List? _deriveKeyUtf8Raw(String key) {
    final bytes = utf8.encode(key);
    if (bytes.isEmpty) return null;
    // Aceita apenas se comprimento é 16, 24 ou 32
    final validLengths = [16, 24, 32];
    if (validLengths.contains(bytes.length)) {
      return Uint8List.fromList(bytes);
    }
    // Padding com zeros ou truncate para 32 bytes
    final result = Uint8List(32);
    for (int i = 0; i < min(bytes.length, 32); i++) {
      result[i] = bytes[i];
    }
    return result;
  }

  /// Converte string hex para bytes
  Uint8List _hexToBytes(String hex) {
    final result = Uint8List(hex.length ~/ 2);
    for (int i = 0; i < result.length; i++) {
      result[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
    }
    return result;
  }

  // ─── Tentativas de decriptação AES ─────────────────────────────

  List<int>? _tryAesCbc(Uint8List data, Uint8List keyBytes) {
    if (data.length < 32) return null;
    // Ajusta key para tamanho válido AES (16, 24 ou 32 bytes)
    final adjustedKey = _adjustKeyLength(keyBytes);
    if (adjustedKey == null) return null;
    try {
      final iv = enc.IV(Uint8List.fromList(data.sublist(0, 16)));
      final key = enc.Key(adjustedKey);
      final cipher = enc.AES(key, mode: enc.AESMode.cbc, padding: 'PKCS7');
      final encrypter = enc.Encrypter(cipher);
      final ciphertext = enc.Encrypted(Uint8List.fromList(data.sublist(16)));
      return encrypter.decryptBytes(ciphertext, iv: iv);
    } catch (_) {
      // Tenta sem padding
      try {
        final adjustedKey2 = _adjustKeyLength(keyBytes);
        if (adjustedKey2 == null) return null;
        final iv = enc.IV(Uint8List.fromList(data.sublist(0, 16)));
        final key = enc.Key(adjustedKey2);
        final cipher = enc.AES(key, mode: enc.AESMode.cbc, padding: null);
        final encrypter = enc.Encrypter(cipher);
        final ciphertext = enc.Encrypted(Uint8List.fromList(data.sublist(16)));
        return encrypter.decryptBytes(ciphertext, iv: iv);
      } catch (_) {
        return null;
      }
    }
  }

  List<int>? _tryAesEcb(Uint8List data, Uint8List keyBytes) {
    final adjustedKey = _adjustKeyLength(keyBytes);
    if (adjustedKey == null) return null;
    try {
      final key = enc.Key(adjustedKey);
      final cipher = enc.AES(key, mode: enc.AESMode.ecb, padding: 'PKCS7');
      final encrypter = enc.Encrypter(cipher);
      final ciphertext = enc.Encrypted(data);
      return encrypter.decryptBytes(ciphertext, iv: enc.IV.allZerosOfLength(16));
    } catch (_) {
      return null;
    }
  }

  /// Ajusta keyBytes para o tamanho AES válido mais próximo (16, 24 ou 32).
  Uint8List? _adjustKeyLength(Uint8List keyBytes) {
    final len = keyBytes.length;
    int targetLen;
    if (len >= 32) {
      targetLen = 32;
    } else if (len >= 24) {
      targetLen = 24;
    } else if (len >= 16) {
      targetLen = 16;
    } else {
      // Chave muito curta: preenche com zeros até 16 bytes
      targetLen = 16;
      final padded = Uint8List(16);
      padded.setRange(0, len, keyBytes);
      return padded;
    }
    if (len == targetLen) return keyBytes;
    return Uint8List.fromList(keyBytes.sublist(0, targetLen));
  }

  // ─── Verificação de JSON ────────────────────────────────────────

  /// Retorna true se os bytes decriptados parecem ser JSON válido.
  ///
  /// JSON deve começar com '{' ou '['. Verifica também que ao menos
  /// 85% dos primeiros 120 bytes são caracteres de texto imprimível,
  /// para descartar resultados de decriptação incorreta (garbage output).
  bool _looksLikeJson(List<int> bytes) {
    if (bytes.isEmpty) return false;

    // Pula bytes nulos iniciais (padding PKCS7 pode deixar zeros)
    int start = 0;
    while (start < bytes.length && bytes[start] == 0) start++;
    if (start >= bytes.length) return false;

    final first = bytes[start];
    // JSON começa com '{' (0x7B) ou '[' (0x5B)
    if (first != 0x7B && first != 0x5B) return false;

    // Verifica proporção de caracteres imprimíveis nos primeiros bytes
    final checkEnd = min(start + 120, bytes.length);
    int printable = 0;
    for (int i = start; i < checkEnd; i++) {
      final b = bytes[i];
      if ((b >= 0x20 && b <= 0x7E) || b == 0x09 || b == 0x0A || b == 0x0D) {
        printable++;
      }
    }
    final ratio = printable / (checkEnd - start);
    return ratio > 0.85;
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

