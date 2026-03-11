# RPG Auto Decryptor — App Flutter
**by Darlan · Fullstack Developer**

Converte o script Python `rpg_auto_decryptor_allinone.py` em um APK Android com UI moderna.

---

## Pré-requisitos

| Ferramenta | Versão mínima | Download |
|---|---|---|
| Flutter SDK | 3.16+ | https://flutter.dev/docs/get-started/install |
| Dart SDK | 3.2+ | incluso no Flutter |
| Android Studio | 2023.1+ | https://developer.android.com/studio |
| Java JDK | 11+ | https://adoptium.net |
| apktool.jar | 2.9+ | https://bitbucket.org/iBotPeaches/apktool/downloads |

---

## Setup Rápido (Windows/Mac)

```bash
# 1. Clone / copie a pasta do projeto
cd rpg_decryptor_flutter

# 2. Instale as dependências
flutter pub get

# 3. Confira dispositivos disponíveis
flutter devices

# 4. Build do APK (debug para testar)
flutter build apk --debug

# 5. Build do APK (release — mais leve)
flutter build apk --release --split-per-abi
```

O APK gerado estará em:
```
build/app/outputs/flutter-apk/app-release.apk
```

---

## Instalar no Android

```bash
# Via USB (ADB)
adb install build/app/outputs/flutter-apk/app-release.apk

# Ou copie o .apk para o celular e abra com gerenciador de arquivos
```

---

## Configuração do apktool no app

1. Baixe o `apktool.jar` de: https://bitbucket.org/iBotPeaches/apktool/downloads
2. Copie para o celular (ex: `/sdcard/Download/apktool.jar`)
3. No app → toque no ícone ⚙️ (canto superior direito)
4. Configure o caminho do `apktool.jar`
5. Certifique-se que Java está instalado (Termux: `pkg install openjdk-17`)

---

## Como usar o app

```
1. Abra o app
2. Toque em "Nenhum APK selecionado" → escolha o APK do jogo RPG
3. (Opcional) Configure o apktool.jar em ⚙️
4. Toque em "Iniciar Decriptação"
5. Acompanhe o progresso no console de logs
6. Após concluir → "Abrir Pasta" para ver os arquivos descriptografados
```

### Se a chave não for detectada automaticamente:
- Toque em "Chave Manual (opcional)"
- Insira a chave encontrada manualmente
- Selecione o tipo (AES-CBC, AES-ECB ou XOR)
- Inicie novamente

---

## Arquitetura do Projeto

```
lib/
├── main.dart                  # Entry point + tema escuro
├── screens/
│   └── home_screen.dart       # UI principal completa
├── services/
│   ├── apk_service.dart       # Descompilação com apktool / extração ZIP
│   ├── analyzer_service.dart  # Busca chave nos arquivos .smali
│   ├── decryptor_service.dart # AES-CBC, AES-ECB, XOR (port do Python)
│   └── decryptor_provider.dart# Estado global (Provider)
├── models/
│   └── decryption_info.dart   # Modelos de dados
└── widgets/
    ├── log_console.dart        # Terminal-style log viewer
    └── step_card.dart          # Cards de progresso e resultado

android/
├── app/
│   ├── build.gradle
│   └── src/main/
│       ├── AndroidManifest.xml        # Permissões de storage
│       ├── kotlin/.../MainActivity.kt  # Platform channel para shell
│       └── res/values/styles.xml
└── build.gradle
```

---

## Dependências Flutter

```yaml
file_picker: ^6.2.1        # Seleção de arquivos APK
permission_handler: ^11.3.0 # Permissões Android
path_provider: ^2.1.2       # Caminhos de armazenamento
encrypt: ^5.0.3             # AES decryption (PointyCastle)
crypto: ^3.0.3              # SHA-256 para derivação de chave
archive: ^3.4.10            # Extração ZIP (APK sem apktool)
provider: ^6.1.2            # Gerenciamento de estado
shared_preferences: ^2.2.2  # Salvar configurações
```

---

## Modos de Operação

### Modo Completo (com Java + apktool)
- Requer Java no PATH
- Requer `apktool.jar` configurado
- Gera `.smali` → detecta chave automaticamente

### Modo Fallback (sem Java)
- Extrai APK diretamente como ZIP (sem `.smali`)
- **Chave manual obrigatória**
- Habilite "Extração direta" nas configurações

---

## Troubleshooting

**"Java não encontrado no PATH"**
→ No Termux: `pkg install openjdk-17`
→ No PC: instale o JDK e adicione ao PATH

**"Nenhum arquivo .enc encontrado"**
→ O jogo pode não usar criptografia padrão de RPG Maker

**"Chave não detectada automaticamente"**
→ Use a seção "Chave Manual" no app
→ Inspecione manualmente o .smali com um editor de texto

**App não consegue acessar arquivos**
→ Vá em Configurações → Apps → RPG Decryptor → Permissões → Armazenamento → "Permitir acesso a todos os arquivos"

---

*Script Python original: `rpg_auto_decryptor_allinone.py`*
*Autor: Darlan — Fullstack Developer, 2026*
