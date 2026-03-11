import 'dart:io';
import 'package:flutter/material.dart';
import 'package:file_picker/file_picker.dart';
import 'package:path/path.dart' as p;
import 'package:provider/provider.dart';
import '../models/decryption_info.dart';
import '../services/decryptor_provider.dart';
import '../widgets/log_console.dart';
import '../widgets/step_card.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  final _manualKeyController = TextEditingController();
  bool _showSettings = false;
  bool _showManualKey = false;

  @override
  void dispose() {
    _manualKeyController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final provider = context.watch<DecryptorProvider>();

    return Scaffold(
      body: SafeArea(
        child: CustomScrollView(
          slivers: [
            // ── App Bar ──────────────────────────────────────────────
            SliverAppBar(
              expandedHeight: 120,
              pinned: true,
              backgroundColor: const Color(0xFF0D0D1A),
              flexibleSpace: FlexibleSpaceBar(
                titlePadding: const EdgeInsets.only(left: 20, bottom: 16),
                title: Row(
                  children: [
                    Container(
                      width: 32,
                      height: 32,
                      decoration: BoxDecoration(
                        gradient: const LinearGradient(
                          colors: [Color(0xFF9B59B6), Color(0xFF5DADE2)],
                        ),
                        borderRadius: BorderRadius.circular(8),
                      ),
                      child: const Icon(
                        Icons.lock_open_rounded,
                        color: Colors.white,
                        size: 20,
                      ),
                    ),
                    const SizedBox(width: 10),
                    const Column(
                      mainAxisSize: MainAxisSize.min,
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          'RPG Auto Decryptor',
                          style: TextStyle(
                            fontSize: 16,
                            fontWeight: FontWeight.bold,
                            color: Colors.white,
                          ),
                        ),
                        Text(
                          'by Darlan · v1.0',
                          style: TextStyle(
                            fontSize: 10,
                            color: Colors.white38,
                          ),
                        ),
                      ],
                    ),
                  ],
                ),
              ),
              actions: [
                IconButton(
                  icon: Icon(
                    _showSettings ? Icons.settings : Icons.settings_outlined,
                    color: Colors.white60,
                  ),
                  onPressed: () => setState(() => _showSettings = !_showSettings),
                  tooltip: 'Configurações',
                ),
              ],
            ),

            // ── Conteúdo ─────────────────────────────────────────────
            SliverPadding(
              padding: const EdgeInsets.all(16),
              sliver: SliverList(
                delegate: SliverChildListDelegate([
                  // Configurações (colapsável)
                  if (_showSettings) ...[
                    _SettingsPanel(onClose: () => setState(() => _showSettings = false)),
                    const SizedBox(height: 12),
                  ],

                  // Card de seleção de APK
                  _ApkSelectorCard(provider: provider),
                  const SizedBox(height: 12),

                  // Card de chave manual (colapsável)
                  _ManualKeyCard(
                    expanded: _showManualKey,
                    controller: _manualKeyController,
                    provider: provider,
                    onToggle: () => setState(() => _showManualKey = !_showManualKey),
                  ),
                  const SizedBox(height: 12),

                  // Botão principal
                  _MainActionButton(provider: provider),
                  const SizedBox(height: 16),

                  // Progresso (visível durante processo)
                  if (provider.currentStep != ProcessStep.idle) ...[
                    StepProgressCard(
                      currentStep: provider.currentStep,
                      progress: provider.progress,
                      filesDecrypted: provider.filesDecrypted,
                      filesTotal: provider.filesTotal,
                    ),
                    const SizedBox(height: 12),
                  ],

                  // Info de criptografia encontrada
                  if (provider.encryptionInfo != null) ...[
                    EncryptionInfoCard(info: provider.encryptionInfo!),
                    const SizedBox(height: 12),
                  ],

                  // Console de logs
                  if (provider.logs.isNotEmpty) ...[
                    Row(
                      children: [
                        const Icon(
                          Icons.terminal_rounded,
                          color: Colors.white38,
                          size: 16,
                        ),
                        const SizedBox(width: 6),
                        const Text(
                          'Log de Execução',
                          style: TextStyle(
                            color: Colors.white38,
                            fontSize: 13,
                          ),
                        ),
                        const Spacer(),
                        TextButton(
                          onPressed: provider.clearLogs,
                          child: const Text(
                            'Limpar',
                            style: TextStyle(fontSize: 12, color: Colors.white30),
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 4),
                    LogConsole(logs: provider.logs),
                    const SizedBox(height: 12),
                  ],

                  // Card de resultado final
                  if (provider.lastResult != null)
                    _ResultCard(result: provider.lastResult!),

                  const SizedBox(height: 32),
                ]),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Widgets locais
// ─────────────────────────────────────────────────────────────────────────────

/// Card de seleção do arquivo APK
class _ApkSelectorCard extends StatelessWidget {
  final DecryptorProvider provider;
  const _ApkSelectorCard({required this.provider});

  Future<void> _pickApk(BuildContext context) async {
    final result = await FilePicker.platform.pickFiles(
      type: FileType.custom,
      allowedExtensions: ['apk'],
      dialogTitle: 'Selecione o APK do jogo RPG',
    );

    if (result != null && result.files.single.path != null) {
      context.read<DecryptorProvider>().setApkPath(result.files.single.path!);
    }
  }

  @override
  Widget build(BuildContext context) {
    final hasApk = provider.apkPath != null && provider.apkPath!.isNotEmpty;
    final apkName = hasApk ? p.basename(provider.apkPath!) : null;
    final apkSize = hasApk
        ? _formatSize(File(provider.apkPath!).lengthSync())
        : null;

    return Card(
      child: InkWell(
        onTap: provider.isRunning ? null : () => _pickApk(context),
        borderRadius: BorderRadius.circular(16),
        child: Padding(
          padding: const EdgeInsets.all(20),
          child: Row(
            children: [
              // Ícone APK
              Container(
                width: 56,
                height: 56,
                decoration: BoxDecoration(
                  color: hasApk
                      ? const Color(0xFF9B59B6).withOpacity(0.15)
                      : const Color(0xFF2D2D4A),
                  borderRadius: BorderRadius.circular(14),
                  border: Border.all(
                    color: hasApk
                        ? const Color(0xFF9B59B6)
                        : const Color(0xFF3D3D5C),
                  ),
                ),
                child: Icon(
                  hasApk ? Icons.android_rounded : Icons.add_rounded,
                  color: hasApk
                      ? const Color(0xFF9B59B6)
                      : Colors.white38,
                  size: 28,
                ),
              ),
              const SizedBox(width: 16),

              // Info
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      hasApk ? apkName! : 'Nenhum APK selecionado',
                      style: TextStyle(
                        color: hasApk ? Colors.white : Colors.white38,
                        fontSize: 15,
                        fontWeight:
                            hasApk ? FontWeight.w500 : FontWeight.normal,
                      ),
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                    ),
                    if (apkSize != null) ...[
                      const SizedBox(height: 4),
                      Text(
                        apkSize,
                        style: const TextStyle(
                          color: Colors.white38,
                          fontSize: 12,
                        ),
                      ),
                    ] else ...[
                      const SizedBox(height: 4),
                      const Text(
                        'Toque para selecionar o APK do jogo',
                        style: TextStyle(color: Colors.white30, fontSize: 12),
                      ),
                    ],
                  ],
                ),
              ),

              // Seta
              Icon(
                Icons.chevron_right_rounded,
                color: hasApk ? const Color(0xFF9B59B6) : Colors.white24,
              ),
            ],
          ),
        ),
      ),
    );
  }

  String _formatSize(int bytes) {
    if (bytes < 1024) return '$bytes B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
    return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
  }
}

/// Card para inserir chave manualmente
class _ManualKeyCard extends StatelessWidget {
  final bool expanded;
  final TextEditingController controller;
  final DecryptorProvider provider;
  final VoidCallback onToggle;

  const _ManualKeyCard({
    required this.expanded,
    required this.controller,
    required this.provider,
    required this.onToggle,
  });

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          children: [
            InkWell(
              onTap: onToggle,
              child: Row(
                children: [
                  const Icon(Icons.vpn_key_rounded,
                      color: Color(0xFFAF7EFF), size: 18),
                  const SizedBox(width: 8),
                  const Text(
                    'Chave Manual (opcional)',
                    style: TextStyle(color: Colors.white70, fontSize: 14),
                  ),
                  const Spacer(),
                  Icon(
                    expanded
                        ? Icons.keyboard_arrow_up
                        : Icons.keyboard_arrow_down,
                    color: Colors.white38,
                  ),
                ],
              ),
            ),
            if (expanded) ...[
              const SizedBox(height: 12),
              TextField(
                controller: controller,
                onChanged: (v) => provider.manualSecretKey = v,
                style: const TextStyle(
                  color: Colors.white,
                  fontFamily: 'monospace',
                  fontSize: 13,
                ),
                decoration: const InputDecoration(
                  labelText: 'Secret Key',
                  hintText: 'Ex: MyS3cr3tK3y@RPG',
                  prefixIcon: Icon(Icons.key, color: Colors.white38, size: 18),
                ),
              ),
              const SizedBox(height: 12),
              Row(
                children: [
                  const Text(
                    'Tipo:',
                    style: TextStyle(color: Colors.white54, fontSize: 13),
                  ),
                  const SizedBox(width: 12),
                  ...[
                    'AES-CBC',
                    'AES-ECB',
                    'XOR',
                  ].map(
                    (type) => Padding(
                      padding: const EdgeInsets.only(right: 8),
                      child: ChoiceChip(
                        label: Text(type),
                        selected: provider.manualEncType == type,
                        onSelected: (_) => provider.manualEncType = type,
                        selectedColor: const Color(0xFF9B59B6),
                        labelStyle: TextStyle(
                          color: provider.manualEncType == type
                              ? Colors.white
                              : Colors.white54,
                          fontSize: 12,
                        ),
                        backgroundColor: const Color(0xFF2D2D4A),
                        side: BorderSide.none,
                      ),
                    ),
                  ),
                ],
              ),
            ],
          ],
        ),
      ),
    );
  }
}

/// Botão de ação principal (Iniciar / Cancelar / Novo)
class _MainActionButton extends StatelessWidget {
  final DecryptorProvider provider;
  const _MainActionButton({required this.provider});

  @override
  Widget build(BuildContext context) {
    if (provider.currentStep == ProcessStep.done) {
      return Row(
        children: [
          Expanded(
            child: ElevatedButton.icon(
              onPressed: provider.reset,
              icon: const Icon(Icons.refresh_rounded),
              label: const Text('Nova Análise'),
              style: ElevatedButton.styleFrom(
                backgroundColor: const Color(0xFF1A1A2E),
                foregroundColor: Colors.white70,
              ),
            ),
          ),
          const SizedBox(width: 12),
          Expanded(
            flex: 2,
            child: ElevatedButton.icon(
              onPressed: () => _openOutputFolder(context, provider),
              icon: const Icon(Icons.folder_open_rounded),
              label: const Text('Abrir Pasta'),
            ),
          ),
        ],
      );
    }

    if (provider.currentStep == ProcessStep.error) {
      return Column(
        children: [
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: const Color(0xFFFF6B6B).withOpacity(0.1),
              borderRadius: BorderRadius.circular(12),
              border: Border.all(
                color: const Color(0xFFFF6B6B).withOpacity(0.3),
              ),
            ),
            child: const Row(
              children: [
                Icon(Icons.error_outline, color: Color(0xFFFF6B6B), size: 18),
                SizedBox(width: 8),
                Expanded(
                  child: Text(
                    'Ocorreu um erro. Verifique os logs e tente novamente.',
                    style: TextStyle(color: Color(0xFFFF6B6B), fontSize: 13),
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 12),
          SizedBox(
            width: double.infinity,
            child: ElevatedButton.icon(
              onPressed: provider.reset,
              icon: const Icon(Icons.refresh_rounded),
              label: const Text('Tentar Novamente'),
            ),
          ),
        ],
      );
    }

    final canRun = provider.apkPath != null && !provider.isRunning;

    return SizedBox(
      width: double.infinity,
      child: ElevatedButton.icon(
        onPressed: canRun ? provider.runFullProcess : null,
        icon: provider.isRunning
            ? const SizedBox(
                width: 18,
                height: 18,
                child: CircularProgressIndicator(
                  strokeWidth: 2,
                  color: Colors.white,
                ),
              )
            : const Icon(Icons.play_arrow_rounded),
        label: Text(
          provider.isRunning
              ? provider.currentStep.label
              : 'Iniciar Decriptação',
          style: const TextStyle(fontSize: 16),
        ),
        style: ElevatedButton.styleFrom(
          padding: const EdgeInsets.symmetric(vertical: 16),
          backgroundColor: canRun
              ? const Color(0xFF9B59B6)
              : const Color(0xFF2D2D4A),
        ),
      ),
    );
  }

  void _openOutputFolder(BuildContext context, DecryptorProvider provider) {
    final folder = provider.lastResult?.outputFolder ?? '';
    if (folder.isEmpty) return;

    try {
      if (Platform.isWindows) {
        Process.run('explorer', [folder]);
      } else if (Platform.isMacOS) {
        Process.run('open', [folder]);
      } else if (Platform.isLinux) {
        Process.run('xdg-open', [folder]);
      }
    } catch (e) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Pasta: $folder')),
      );
    }
  }
}

/// Card de resultado final
class _ResultCard extends StatelessWidget {
  final DecryptionResult result;
  const _ResultCard({required this.result});

  @override
  Widget build(BuildContext context) {
    return Card(
      color: result.success
          ? const Color(0xFF0D2B1A)
          : const Color(0xFF2B0D0D),
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(16),
        side: BorderSide(
          color: result.success
              ? const Color(0xFF6BCB77).withOpacity(0.4)
              : const Color(0xFFFF6B6B).withOpacity(0.4),
        ),
      ),
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Row(
          children: [
            Icon(
              result.success
                  ? Icons.check_circle_rounded
                  : Icons.cancel_rounded,
              color: result.success
                  ? const Color(0xFF6BCB77)
                  : const Color(0xFFFF6B6B),
              size: 36,
            ),
            const SizedBox(width: 16),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    result.success
                        ? '${result.filesDecrypted} arquivo(s) descriptografado(s)!'
                        : 'Falha na decriptação',
                    style: TextStyle(
                      color: result.success
                          ? const Color(0xFF6BCB77)
                          : const Color(0xFFFF6B6B),
                      fontWeight: FontWeight.bold,
                      fontSize: 15,
                    ),
                  ),
                  if (result.outputFolder.isNotEmpty) ...[
                    const SizedBox(height: 4),
                    Text(
                      result.outputFolder,
                      style: const TextStyle(
                        color: Colors.white38,
                        fontSize: 12,
                      ),
                      maxLines: 2,
                      overflow: TextOverflow.ellipsis,
                    ),
                  ],
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}

/// Painel de configurações
class _SettingsPanel extends StatefulWidget {
  final VoidCallback onClose;
  const _SettingsPanel({required this.onClose});

  @override
  State<_SettingsPanel> createState() => _SettingsPanelState();
}

class _SettingsPanelState extends State<_SettingsPanel> {
  late final TextEditingController _javaPathController;

  @override
  void initState() {
    super.initState();
    _javaPathController = TextEditingController(
      text: context.read<DecryptorProvider>().javaPath,
    );
  }

  @override
  void dispose() {
    _javaPathController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final provider = context.watch<DecryptorProvider>();

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Icon(Icons.settings_rounded,
                    color: Color(0xFF9B59B6), size: 20),
                const SizedBox(width: 8),
                const Text(
                  'Configurações',
                  style: TextStyle(
                    color: Colors.white,
                    fontSize: 16,
                    fontWeight: FontWeight.w600,
                  ),
                ),
                const Spacer(),
                IconButton(
                  icon: const Icon(Icons.close, color: Colors.white38, size: 18),
                  onPressed: widget.onClose,
                  padding: EdgeInsets.zero,
                  constraints: const BoxConstraints(),
                ),
              ],
            ),
            const SizedBox(height: 16),

            // ── Caminho do Java ──────────────────────────────────────
            const Text(
              'Caminho do Java (opcional)',
              style: TextStyle(color: Colors.white54, fontSize: 13),
            ),
            const SizedBox(height: 4),
            const Text(
              'Vazio = usa o Java do PATH. No Termux use o caminho abaixo:',
              style: TextStyle(color: Colors.white30, fontSize: 11),
            ),
            const SizedBox(height: 2),
            GestureDetector(
              onTap: () {
                _javaPathController.text =
                    '/data/data/com.termux/files/usr/bin/java';
                provider.setJavaPath(_javaPathController.text);
              },
              child: const Text(
                '/data/data/com.termux/files/usr/bin/java  (toque para preencher)',
                style: TextStyle(
                  color: Color(0xFF5DADE2),
                  fontSize: 11,
                  decoration: TextDecoration.underline,
                  decorationColor: Color(0xFF5DADE2),
                ),
              ),
            ),
            const SizedBox(height: 6),
            TextField(
              controller: _javaPathController,
              onChanged: provider.setJavaPath,
              style: const TextStyle(
                color: Colors.white70,
                fontFamily: 'monospace',
                fontSize: 12,
              ),
              decoration: InputDecoration(
                hintText: 'Ex: /data/data/com.termux/files/usr/bin/java',
                prefixIcon: const Icon(Icons.coffee_rounded,
                    color: Colors.white38, size: 18),
                suffixIcon: provider.javaPath.isNotEmpty
                    ? IconButton(
                        icon: const Icon(Icons.clear,
                            color: Colors.white30, size: 16),
                        onPressed: () {
                          _javaPathController.clear();
                          provider.setJavaPath('');
                        },
                      )
                    : null,
                contentPadding:
                    const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
              ),
            ),
            const SizedBox(height: 12),

            // ── apktool.jar ──────────────────────────────────────────
            const Text(
              'Caminho do apktool.jar',
              style: TextStyle(color: Colors.white54, fontSize: 13),
            ),
            const SizedBox(height: 6),
            Row(
              children: [
                Expanded(
                  child: Container(
                    padding: const EdgeInsets.symmetric(
                        horizontal: 12, vertical: 10),
                    decoration: BoxDecoration(
                      color: const Color(0xFF0D0D1A),
                      borderRadius: BorderRadius.circular(10),
                      border: Border.all(color: const Color(0xFF3D3D5C)),
                    ),
                    child: Text(
                      provider.apktoolJarPath ?? 'Não configurado',
                      style: TextStyle(
                        color: provider.apktoolJarPath != null
                            ? Colors.white70
                            : Colors.white24,
                        fontSize: 12,
                        fontFamily: 'monospace',
                      ),
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                    ),
                  ),
                ),
                const SizedBox(width: 8),
                ElevatedButton(
                  onPressed: () => _pickApktool(context),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: const Color(0xFF2D2D4A),
                    padding: const EdgeInsets.symmetric(
                        horizontal: 12, vertical: 10),
                  ),
                  child: const Text('Procurar', style: TextStyle(fontSize: 13)),
                ),
              ],
            ),
            const SizedBox(height: 12),

            // Pasta de saída
            const Text(
              'Pasta de saída (opcional)',
              style: TextStyle(color: Colors.white54, fontSize: 13),
            ),
            const SizedBox(height: 6),
            Row(
              children: [
                Expanded(
                  child: Container(
                    padding: const EdgeInsets.symmetric(
                        horizontal: 12, vertical: 10),
                    decoration: BoxDecoration(
                      color: const Color(0xFF0D0D1A),
                      borderRadius: BorderRadius.circular(10),
                      border: Border.all(color: const Color(0xFF3D3D5C)),
                    ),
                    child: Text(
                      provider.outputFolder.isEmpty
                          ? 'Padrão (temp/decrypted)'
                          : provider.outputFolder,
                      style: TextStyle(
                        color: provider.outputFolder.isNotEmpty
                            ? Colors.white70
                            : Colors.white24,
                        fontSize: 12,
                      ),
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                    ),
                  ),
                ),
                const SizedBox(width: 8),
                ElevatedButton(
                  onPressed: () => _pickOutputFolder(context),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: const Color(0xFF2D2D4A),
                    padding: const EdgeInsets.symmetric(
                        horizontal: 12, vertical: 10),
                  ),
                  child: const Text('Mudar', style: TextStyle(fontSize: 13)),
                ),
              ],
            ),
            const SizedBox(height: 12),

            // Toggle extração direta
            Row(
              children: [
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: const [
                      Text(
                        'Extração direta (sem Java)',
                        style: TextStyle(color: Colors.white70, fontSize: 13),
                      ),
                      Text(
                        'Ignora o apktool. Sem .smali = chave manual obrigatória.',
                        style: TextStyle(color: Colors.white30, fontSize: 11),
                      ),
                    ],
                  ),
                ),
                Switch(
                  value: provider.useDirectExtraction,
                  onChanged: (v) {
                    provider.useDirectExtraction = v;
                    provider.savePreferences();
                  },
                  activeColor: const Color(0xFF9B59B6),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Future<void> _pickApktool(BuildContext context) async {
    final result = await FilePicker.platform.pickFiles(
      type: FileType.custom,
      allowedExtensions: ['jar'],
      dialogTitle: 'Selecione o apktool.jar',
    );
    if (result?.files.single.path != null) {
      context.read<DecryptorProvider>().setApktoolPath(
            result!.files.single.path!,
          );
    }
  }

  Future<void> _pickOutputFolder(BuildContext context) async {
    final result = await FilePicker.platform.getDirectoryPath(
      dialogTitle: 'Selecione a pasta de saída',
    );
    if (result != null) {
      context.read<DecryptorProvider>().setOutputFolder(result);
    }
  }
}
