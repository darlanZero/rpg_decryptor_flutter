import 'dart:typed_data';

/// Parser do formato binário DEX (Dalvik Executable).
///
/// Extrai a tabela de strings diretamente do bytecode Dalvik sem necessidade
/// de Java, apktool ou baksmali.
///
/// Formato DEX:
///   Offset  Size  Description
///   0       8     Magic ("dex\n039\0")
///   8       4     Checksum (Adler32)
///   12      20    SHA-1 signature
///   32      4     file_size
///   36      4     header_size (0x70 = 112)
///   40      4     endian_tag (0x12345678)
///   44-51   8     link_size + link_off
///   52      4     map_off
///   56      4     string_ids_size  ← número de strings
///   60      4     string_ids_off   ← offset da tabela de IDs de strings
///   ... (outros campos que não precisamos)
///
/// Cada string_id é um uint32 apontando para um string_data_item:
///   [ULEB128 utf16_size] [bytes MUTF-8] [0x00 terminador]
class DexParser {
  final Uint8List _bytes;
  late final ByteData _data;

  DexParser(Uint8List bytes)
      : _bytes = bytes,
        _data = ByteData.view(bytes.buffer, bytes.offsetInBytes, bytes.lengthInBytes);

  // Versões válidas do magic DEX
  static const _validMagics = {
    'dex\n035\x00',
    'dex\n036\x00',
    'dex\n037\x00',
    'dex\n038\x00',
    'dex\n039\x00',
    'dex\n040\x00',
  };

  // Tamanho mínimo do header DEX
  static const _headerSize = 112;

  /// Verifica se os bytes representam um arquivo DEX válido
  bool get isValidDex {
    if (_bytes.length < _headerSize) return false;
    final magic = String.fromCharCodes(_bytes.take(8));
    return _validMagics.contains(magic);
  }

  /// Versão do formato DEX (ex: "039")
  String get version {
    if (_bytes.length < 8) return 'unknown';
    return String.fromCharCodes(_bytes.sublist(4, 7));
  }

  // ─────────────────────────────────────────────────────────────────
  // Extração da tabela de strings
  // ─────────────────────────────────────────────────────────────────

  /// Extrai todas as constantes de string da tabela de strings do DEX.
  ///
  /// Retorna uma lista com todas as strings, incluindo nomes de classes
  /// (formato "Lcom/example/Class;"), nomes de métodos e literais de string.
  ///
  /// Use [filterForKeys] para retornar apenas candidatos a chave de criptografia.
  List<String> extractAllStrings({bool filterForKeys = false}) {
    if (!isValidDex) return [];

    try {
      final stringIdsSize = _readUint32(56);
      final stringIdsOff = _readUint32(60);

      // Sanity checks
      if (stringIdsSize == 0 || stringIdsSize > 1000000) return [];
      if (stringIdsOff < _headerSize || stringIdsOff >= _bytes.length) return [];

      final strings = <String>[];

      for (int i = 0; i < stringIdsSize; i++) {
        final idOff = stringIdsOff + (i * 4);
        if (idOff + 4 > _bytes.length) break;

        final strDataOff = _readUint32(idOff);
        if (strDataOff >= _bytes.length) continue;

        final str = _readMutf8String(strDataOff);
        if (str == null || str.isEmpty) continue;

        if (filterForKeys) {
          if (_isKeyCandidate(str)) strings.add(str);
        } else {
          strings.add(str);
        }
      }

      return strings;
    } catch (_) {
      return [];
    }
  }

  /// Verifica se o DEX contém referências a APIs de criptografia
  bool hasCryptoReferences() {
    if (!isValidDex) return false;
    final strings = extractAllStrings();
    return strings.any((s) =>
        s.contains('AES') ||
        s.contains('cipher') ||
        s.contains('Cipher') ||
        s.contains('encrypt') ||
        s.contains('Encrypt') ||
        s.contains('javax/crypto') ||
        s.contains('SecretKey'));
  }

  /// Detecta o tipo de criptografia referenciado no DEX
  String detectEncryptionType() {
    if (!isValidDex) return 'AES-CBC';
    final strings = extractAllStrings();
    if (strings.any((s) => s.contains('AES/CBC'))) return 'AES-CBC';
    if (strings.any((s) => s.contains('AES/ECB'))) return 'AES-ECB';
    if (strings.any((s) => s.contains('AES'))) return 'AES-CBC';
    if (strings.any((s) => s == 'XOR' || s == 'xor')) return 'XOR';
    return 'AES-CBC';
  }

  // ─────────────────────────────────────────────────────────────────
  // Leitura de MUTF-8 (Modified UTF-8 do formato DEX)
  // Diferença do UTF-8 padrão: null char é 0xC0 0x80 ao invés de 0x00
  // ─────────────────────────────────────────────────────────────────

  String? _readMutf8String(int offset) {
    if (offset >= _bytes.length) return null;

    try {
      int pos = offset;

      // Lê o comprimento em ULEB128 (número de chars UTF-16)
      // Precisamos pular esse valor para chegar nos bytes da string
      int uleb128ByteCount = 0;
      while (pos < _bytes.length && uleb128ByteCount < 5) {
        final b = _bytes[pos++];
        uleb128ByteCount++;
        if ((b & 0x80) == 0) break; // bit mais significativo = 0 → último byte
      }

      // Lê os bytes da string até o null terminator
      final buffer = StringBuffer();
      int charCount = 0;
      const maxChars = 512; // limite para performance

      while (pos < _bytes.length && charCount < maxChars) {
        final b = _bytes[pos];

        if (b == 0x00) break; // null terminator normal

        if (b < 0x80) {
          // ASCII (1 byte)
          buffer.writeCharCode(b);
          pos++;
        } else if ((b & 0xE0) == 0xC0) {
          // 2 bytes (inclui MUTF-8 null: 0xC0 0x80)
          if (pos + 1 >= _bytes.length) break;
          final next = _bytes[pos + 1];
          final codePoint = ((b & 0x1F) << 6) | (next & 0x3F);
          if (codePoint != 0) buffer.writeCharCode(codePoint);
          pos += 2;
        } else if ((b & 0xF0) == 0xE0) {
          // 3 bytes (BMP)
          if (pos + 2 >= _bytes.length) break;
          final codePoint = ((b & 0x0F) << 12) |
              ((_bytes[pos + 1] & 0x3F) << 6) |
              (_bytes[pos + 2] & 0x3F);
          buffer.writeCharCode(codePoint);
          pos += 3;
        } else if ((b & 0xF8) == 0xF0) {
          // 4 bytes (supplementary) — raro em DEX, pula
          pos += 4;
        } else {
          // Byte inválido, pula
          pos++;
        }

        charCount++;
      }

      return buffer.toString();
    } catch (_) {
      return null;
    }
  }

  // ─────────────────────────────────────────────────────────────────
  // Heurísticas para identificar candidatos a chave
  // ─────────────────────────────────────────────────────────────────

  bool _isKeyCandidate(String s) {
    final len = s.length;

    // Comprimento típico de chaves: 16 a 64 chars
    if (len < 16 || len > 64) return false;

    // Exclui nomes de classes Java (Lcom/...; ou [B, etc)
    if (s.startsWith('L') && s.endsWith(';')) return false;
    if (s.startsWith('[')) return false;

    // Exclui padrões que claramente não são chaves
    if (s.contains('.') || s.contains('/') || s.contains('\\')) return false;
    if (s.contains('<') || s.contains('>') || s.contains('(')) return false;
    if (s.contains(' ')) return false;

    // Chave hex (32 chars = AES-128, 48 = AES-192, 64 = AES-256)
    if (RegExp(r'^[0-9a-fA-F]+$').hasMatch(s) &&
        (len == 32 || len == 48 || len == 64)) {
      return true;
    }

    // Chave alfanumérica mista (string literal da chave)
    final hasDigit = s.contains(RegExp(r'\d'));
    final hasLower = s.contains(RegExp(r'[a-z]'));
    final hasUpper = s.contains(RegExp(r'[A-Z]'));

    // Exige mix de caracteres (evita falsos positivos como palavras normais)
    if (hasDigit && (hasLower || hasUpper)) {
      // Rejeita se parece ser um número de versão ou hash de recurso
      if (RegExp(r'^\d+\.\d+').hasMatch(s)) return false;
      if (RegExp(r'^[0-9A-F]{8}$').hasMatch(s)) return false; // Cor ARGB

      return true;
    }

    // Strings base64 longas
    if (RegExp(r'^[A-Za-z0-9+/]{24,}={0,2}$').hasMatch(s) && len >= 24) {
      return true;
    }

    return false;
  }

  // ─────────────────────────────────────────────────────────────────
  // Helpers
  // ─────────────────────────────────────────────────────────────────

  int _readUint32(int offset) {
    if (offset + 4 > _bytes.length) {
      throw RangeError('DEX: offset $offset fora dos limites (tamanho: ${_bytes.length})');
    }
    return _data.getUint32(offset, Endian.little);
  }
}
