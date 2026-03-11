# RPG Auto Decryptor — App Flutter

**by Darlan · Fullstack Developer & Analista de Sistemas**

Port do script Python `rpg_auto_decryptor_allinone.py` em APK Android nativo com UI moderna e tema dark gaming. Toda a lógica de decriptação foi reimplementada em Dart puro — sem dependência de servidor Python.

---

## Visão Geral

O app analisa APKs de jogos RPG Maker para Android, detecta automaticamente a chave de criptografia nos arquivos `.smali` e descriptografa todos os assets `.enc` do jogo. Suporta AES-CBC, AES-ECB e XOR.

**Fluxo principal:**

```
APK do jogo → Descompilação (apktool) → Análise .smali → Detecção de chave → Decriptação assets
```

---

## Stack de Tecnologia

| Componente | Versão | Observação |
|---|---|---|
| Flutter SDK | **3.41.4** | Cross-platform framework |
| Dart SDK | **3.11.1** | Incluso no Flutter |
| Android Gradle Plugin (AGP) | **8.7.0** | Requer Java 21 no host |
| Gradle Wrapper | **8.9** | Mínimo para suporte ao Java 21 |
| Kotlin | **2.1.0** | Plugin Android |
| Java (compilação host) | **17+ ou 21** | JDK na máquina de build |
| `minSdk` Android | **21** | Android 5.0+ |
| `targetSdk` Android | **34** | Android 14 |
| `compileSdk` Android | **35** | |

---

## Dependências Flutter (pubspec.yaml)

```yaml
dependencies:
  flutter:
    sdk: flutter

  # Seleção de arquivos (APK, apktool.jar, etc.)
  file_picker: ^8.0.0            # ⚠️ v8+ obrigatória — v6.x usa Flutter embedding v1 removido

  # Permissões Android runtime
  permission_handler: ^11.3.0

  # Caminhos de armazenamento do sistema
  path_provider: ^2.1.2

  # AES decryption (PointyCastle internamente)
  encrypt: ^5.0.3

  # SHA-256 para derivação de chave
  crypto: ^3.0.3

  # Extração ZIP do APK (modo sem Java)
  archive: ^3.4.10

  # Gerenciamento de estado (ChangeNotifier/Provider)
  provider: ^6.1.2

  # Persistência de configurações
  shared_preferences: ^2.2.2
```

> **Atenção:** `file_picker: ^6.2.1` **não compila** com AGP 8.7+ pois usa `PluginRegistry.Registrar` (API Flutter v1 removida). Use sempre `^8.0.0`.

---

## Pré-requisitos para Build (Windows / macOS / Linux)

| Ferramenta | Versão mínima | Link |
|---|---|---|
| Flutter SDK | 3.41.4 | https://flutter.dev/docs/get-started/install |
| JDK (host de build) | 17 ou 21 | https://adoptium.net |
| Android Studio | 2024.1+ | https://developer.android.com/studio |
| Android SDK | API 35 | Via Android Studio SDK Manager |

> O Flutter 3.41.4 usa AGP 8.7.0 + Gradle 8.9, que exigem **Java 17 ou 21** na máquina de compilação. Java 11 causará erro de `Unsupported class file major version 65`.

---

## Setup e Build

```bash
# 1. Entre na pasta do projeto
cd rpg_decryptor_flutter

# 2. Instale as dependências
flutter pub get

# 3. Verifique os dispositivos conectados
flutter devices

# 4. Build debug (para testes)
flutter build apk --debug

# 5. Build release (produção, menor tamanho)
flutter build apk --release --split-per-abi
```

APKs gerados em:
```
build/app/outputs/flutter-apk/
  app-armeabi-v7a-release.apk   ← dispositivos antigos (32-bit)
  app-arm64-v8a-release.apk     ← maioria dos celulares modernos (64-bit)
  app-x86_64-release.apk        ← emuladores x86
```

### Instalar no Android via ADB

```bash
adb install build/app/outputs/flutter-apk/app-arm64-v8a-release.apk
```

Ou copie o `.apk` diretamente para o celular e instale pelo gerenciador de arquivos (habilite "Fontes desconhecidas").

---

## Configuração no Celular (Pré-requisitos em Runtime)

### 1. Java — Instalação via Termux (recomendado)

O app usa `java` para executar o `apktool.jar`. No Android, o Java **não está no PATH do sistema**, então é necessário instalar via Termux e informar o caminho absoluto ao app.

```bash
# No Termux:
pkg update && pkg upgrade
pkg install openjdk-17
```

Após instalar, o executável estará em:
```
/data/data/com.termux/files/usr/bin/java
```

### 2. Caminho Java no App

1. Abra o app → toque em ⚙️ (canto superior direito)
2. No campo **"Caminho do Java (opcional)"**, insira:
   ```
   /data/data/com.termux/files/usr/bin/java
   ```
   Ou toque no link **"Usar caminho do Termux"** para preencher automaticamente.
3. Salve — o app persistirá o caminho entre sessões.

> Se o campo ficar vazio, o app tenta usar `java` do PATH do sistema (funciona em emuladores e dispositivos com Java nativo, raramente em produção).

### 3. APKTool

1. Baixe `apktool.jar` em: https://bitbucket.org/iBotPeaches/apktool/downloads
2. Copie para o celular (ex: `/sdcard/Download/apktool.jar`)
3. No app → ⚙️ → campo **"Caminho do apktool.jar"** → selecione o arquivo

---

## Como Usar o App

```
1. Abra o RPG Auto Decryptor
2. Toque em "Nenhum APK selecionado" → escolha o APK do jogo RPG Maker
3. (Opcional) Configure apktool.jar e caminho Java em ⚙️
4. Toque em "Iniciar Decriptação"
5. Acompanhe o progresso nas etapas e no console de logs
6. Após concluir → "Abrir Pasta" para ver os assets descriptografados
```

### Inserção de Chave Manual

Se a chave não for detectada automaticamente nos arquivos `.smali`:

1. Toque em **"Chave Manual (opcional)"**
2. Insira a chave encontrada manualmente
3. Selecione o tipo: **AES-CBC**, **AES-ECB** ou **XOR**
4. Inicie a decriptação novamente

---

## Modos de Operação

### Modo Completo (com Java + apktool)
- Java configurado → apktool descompila o APK → gera arquivos `.smali`
- O `AnalyzerService` varre os `.smali` com regex para detectar a chave automaticamente
- Detecta: `const-string`, `.field SECRET`, strings alfanuméricas ≥ 20 chars
- Identifica tipo: `AES/CBC/PKCS5Padding`, `AES/ECB/PKCS5Padding`, XOR

### Modo Fallback (sem Java / Extração Direta)
- Extrai o APK diretamente como ZIP (não gera `.smali`)
- **Chave manual obrigatória** — sem análise automática possível
- Ative **"Extração direta (sem Java)"** nas configurações ⚙️

---

## Arquitetura do Projeto

```
rpg_decryptor_flutter/
├── pubspec.yaml
│
├── lib/
│   ├── main.dart                    # Entry point + MaterialApp + tema dark purple
│   ├── screens/
│   │   └── home_screen.dart         # UI completa (painel de config, console, steps)
│   ├── services/
│   │   ├── apk_service.dart         # Runner apktool (javaExecutable param) + extração ZIP
│   │   ├── analyzer_service.dart    # Parser .smali — regex para chaves AES/XOR
│   │   ├── decryptor_service.dart   # AES-CBC, AES-ECB, XOR + derivação SHA-256
│   │   └── decryptor_provider.dart  # ChangeNotifier — estado global + SharedPreferences
│   ├── models/
│   │   └── decryption_info.dart     # EncryptionInfo, DecryptionResult, ProcessStep enum
│   └── widgets/
│       ├── log_console.dart         # Terminal-style log viewer (macOS dots header)
│       └── step_card.dart           # StepProgressCard + EncryptionInfoCard
│
└── android/
    ├── settings.gradle              # Flutter 3.16+ plugin management (AGP 8.7.0, Kotlin 2.1.0)
    ├── build.gradle                 # allprojects repos + clean task (sem buildscript block)
    ├── gradle.properties
    ├── gradle/wrapper/
    │   └── gradle-wrapper.properties  # gradle-8.9-all.zip
    └── app/
        ├── build.gradle             # minSdk 21, JavaVersion.VERSION_11, compileSdk 35
        └── src/main/
            ├── AndroidManifest.xml             # READ/WRITE_EXTERNAL_STORAGE, MANAGE_EXTERNAL_STORAGE
            ├── kotlin/.../MainActivity.kt       # MethodChannel: runCommand, getExternalStorage
            └── res/
                ├── drawable/
                │   └── ic_launcher_foreground.xml   # Vector drawable — ícone cadeado
                ├── mipmap-anydpi-v26/
                │   ├── ic_launcher.xml              # Adaptive icon (API 26+)
                │   └── ic_launcher_round.xml
                ├── mipmap-{mdpi,hdpi,xhdpi,xxhdpi,xxxhdpi}/
                │   └── ic_launcher.png              # PNGs gerados (48–192px)
                └── values/
                    ├── colors.xml                   # ic_launcher_background: #9B59B6
                    └── styles.xml                   # LaunchTheme + NormalTheme (dark)
```

---

## Tema Visual

| Elemento | Valor |
|---|---|
| Cor primária | `#9B59B6` (roxo) |
| Fundo principal | `#0D0D1A` (dark navy) |
| Fundo de cards | `#1A1A2E` |
| Fundo de surface | `#16213E` |
| Fonte | Sistema (sem fonte customizada) |
| Ícone do app | Cadeado roxo sobre fundo `#9B59B6` |

---

## Platform Channel (Android ↔ Flutter)

O `MainActivity.kt` expõe um `MethodChannel` (`com.darlan.rpgdecryptor/shell`) com dois métodos:

| Método | Descrição |
|---|---|
| `runCommand` | Executa um comando shell e retorna `stdout` |
| `getExternalStorage` | Retorna o caminho do armazenamento externo principal |

Usado pelo `ApkService` para invocar o `apktool.jar` via Java no dispositivo.

---

## Troubleshooting

**"Java não encontrado" / apktool não executa**
→ Configure o caminho absoluto em ⚙️: `/data/data/com.termux/files/usr/bin/java`
→ Verifique se o Termux está instalado e o OpenJDK 17 foi instalado com `pkg install openjdk-17`

**"Nenhum arquivo .enc encontrado"**
→ O jogo pode não usar criptografia padrão de RPG Maker
→ Verifique se o APK é de um jogo RPG Maker MV/MZ/VX Ace

**"Chave não detectada automaticamente"**
→ Use a seção **Chave Manual** no app
→ Inspecione manualmente os arquivos `.smali` — procure por `const-string` com strings ≥ 20 chars alfanuméricos

**"App não consegue acessar arquivos externos"**
→ Vá em Configurações → Apps → RPG Decryptor → Permissões → Armazenamento
→ Selecione **"Permitir acesso a todos os arquivos"** (MANAGE_EXTERNAL_STORAGE — Android 11+)

**Build falha com `Unsupported class file major version 65`**
→ Significa que o AGP compilado requer Java 21. Certifique-se que `JAVA_HOME` aponta para JDK 17 ou 21.
→ Confirme que `gradle-wrapper.properties` usa `gradle-8.9-all.zip`

**Build falha com `cannot find symbol: class Registrar`**
→ `file_picker` desatualizado. Atualize para `^8.0.0` no `pubspec.yaml`

**Build falha com `resource mipmap/ic_launcher not found`**
→ Os PNGs dos ícones estão ausentes. Gere com o script Python na raiz ou copie manualmente para as pastas `mipmap-*`

---

## Histórico de Correções de Build

| Problema | Causa | Solução |
|---|---|---|
| `CardTheme` type mismatch | `ThemeData.cardTheme` exige `CardThemeData?` | Trocado `CardTheme(` → `CardThemeData(` |
| `TimeoutException` not a type | `dart:async` não importado | Adicionado `import 'dart:async'` + reordenados catches |
| `Unsupported class file major version 65` | AGP 8.1 + Gradle 8.0 incompatíveis com Java 21 | AGP → 8.7.0, Gradle → 8.9, Kotlin → 2.1.0 |
| `cannot find symbol: class Registrar` | `file_picker` 6.2.1 usa Flutter embedding v1 removido | Atualizado para `file_picker: ^8.0.0` |
| `resource mipmap/ic_launcher not found` | Nenhum PNG de ícone existia no projeto | Gerados PNGs 48–192px + XMLs adaptive icon |
| `attribute android:cx not found` | `<circle>` não é elemento válido em VectorDrawable Android | Substituído por `<path>` com arco SVG equivalente |

---

## Script Python Original

O script `rpg_auto_decryptor_allinone.py` na raiz do repositório é a referência original. Ele opera via linha de comando no Termux com caminhos fixos (`~/storage/downloads/`). Este app Flutter reimplementa toda sua lógica em Dart com UI completa e suporte a caminhos configuráveis.

---

*Autor: Darlan — Fullstack Developer & Analista de Sistemas · 2026*
