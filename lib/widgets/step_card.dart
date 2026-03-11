import 'package:flutter/material.dart';
import '../models/decryption_info.dart';

/// Card que mostra o progresso de cada etapa
class StepProgressCard extends StatelessWidget {
  final ProcessStep currentStep;
  final double progress;
  final int filesDecrypted;
  final int filesTotal;

  const StepProgressCard({
    super.key,
    required this.currentStep,
    required this.progress,
    required this.filesDecrypted,
    required this.filesTotal,
  });

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Icon(Icons.timeline, color: Color(0xFF9B59B6), size: 20),
                const SizedBox(width: 8),
                const Text(
                  'Progresso',
                  style: TextStyle(
                    color: Colors.white,
                    fontSize: 16,
                    fontWeight: FontWeight.w600,
                  ),
                ),
                const Spacer(),
                Text(
                  '${(progress * 100).toInt()}%',
                  style: const TextStyle(
                    color: Color(0xFF9B59B6),
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 16),

            // Barra de progresso
            ClipRRect(
              borderRadius: BorderRadius.circular(8),
              child: LinearProgressIndicator(
                value: progress,
                backgroundColor: const Color(0xFF2D2D4A),
                valueColor: AlwaysStoppedAnimation<Color>(
                  _progressColor(currentStep),
                ),
                minHeight: 8,
              ),
            ),
            const SizedBox(height: 16),

            // Etapas
            _StepRow(
              icon: Icons.unarchive_rounded,
              label: 'Descompilar APK',
              state: _stepState(ProcessStep.decompiling),
            ),
            const SizedBox(height: 8),
            _StepRow(
              icon: Icons.search_rounded,
              label: 'Analisar Criptografia',
              state: _stepState(ProcessStep.analyzing),
            ),
            const SizedBox(height: 8),
            _StepRow(
              icon: Icons.lock_open_rounded,
              label: filesTotal > 0
                  ? 'Descriptografar ($filesDecrypted/$filesTotal arquivos)'
                  : 'Descriptografar Arquivos',
              state: _stepState(ProcessStep.decrypting),
            ),
          ],
        ),
      ),
    );
  }

  _StepState _stepState(ProcessStep step) {
    if (currentStep == ProcessStep.idle) return _StepState.pending;
    if (currentStep == ProcessStep.done) return _StepState.done;
    if (currentStep == ProcessStep.error) {
      // Marca como erro somente a etapa atual quando deu erro
      return _StepState.done;
    }

    final order = [
      ProcessStep.decompiling,
      ProcessStep.analyzing,
      ProcessStep.decrypting,
    ];

    final currentIdx = order.indexOf(currentStep);
    final stepIdx = order.indexOf(step);

    if (stepIdx < currentIdx) return _StepState.done;
    if (stepIdx == currentIdx) return _StepState.active;
    return _StepState.pending;
  }

  Color _progressColor(ProcessStep step) {
    if (step == ProcessStep.done) return const Color(0xFF6BCB77);
    if (step == ProcessStep.error) return const Color(0xFFFF6B6B);
    return const Color(0xFF9B59B6);
  }
}

enum _StepState { pending, active, done }

class _StepRow extends StatelessWidget {
  final IconData icon;
  final String label;
  final _StepState state;

  const _StepRow({
    required this.icon,
    required this.label,
    required this.state,
  });

  @override
  Widget build(BuildContext context) {
    Color color;
    Widget indicator;

    switch (state) {
      case _StepState.done:
        color = const Color(0xFF6BCB77);
        indicator = const Icon(Icons.check_circle, color: Color(0xFF6BCB77), size: 18);
        break;
      case _StepState.active:
        color = const Color(0xFF9B59B6);
        indicator = const SizedBox(
          width: 18,
          height: 18,
          child: CircularProgressIndicator(
            strokeWidth: 2,
            valueColor: AlwaysStoppedAnimation(Color(0xFF9B59B6)),
          ),
        );
        break;
      case _StepState.pending:
        color = Colors.white30;
        indicator = Icon(icon, color: Colors.white30, size: 18);
        break;
    }

    return Row(
      children: [
        indicator,
        const SizedBox(width: 10),
        Text(
          label,
          style: TextStyle(
            color: color,
            fontSize: 14,
            fontWeight:
                state == _StepState.active ? FontWeight.w600 : FontWeight.normal,
          ),
        ),
      ],
    );
  }
}

/// Card que exibe as informações de criptografia encontradas
class EncryptionInfoCard extends StatelessWidget {
  final EncryptionInfo info;

  const EncryptionInfoCard({super.key, required this.info});

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: const [
                Icon(Icons.key_rounded, color: Color(0xFFAF7EFF), size: 20),
                SizedBox(width: 8),
                Text(
                  'Criptografia Detectada',
                  style: TextStyle(
                    color: Colors.white,
                    fontSize: 16,
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 16),
            _InfoRow(
              label: 'Tipo',
              value: info.encryptionType,
              valueColor: const Color(0xFF5DADE2),
            ),
            const SizedBox(height: 8),
            _InfoRow(
              label: 'Chave',
              value: info.secretKey.length > 32
                  ? '${info.secretKey.substring(0, 32)}...'
                  : info.secretKey,
              valueColor: const Color(0xFFAF7EFF),
              monospace: true,
            ),
            const SizedBox(height: 8),
            _InfoRow(
              label: 'Fonte',
              value: info.sourceFile,
              valueColor: Colors.white54,
            ),
          ],
        ),
      ),
    );
  }
}

class _InfoRow extends StatelessWidget {
  final String label;
  final String value;
  final Color valueColor;
  final bool monospace;

  const _InfoRow({
    required this.label,
    required this.value,
    required this.valueColor,
    this.monospace = false,
  });

  @override
  Widget build(BuildContext context) {
    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        SizedBox(
          width: 60,
          child: Text(
            label,
            style: const TextStyle(color: Colors.white38, fontSize: 13),
          ),
        ),
        Expanded(
          child: Text(
            value,
            style: TextStyle(
              color: valueColor,
              fontSize: 13,
              fontFamily: monospace ? 'monospace' : null,
            ),
          ),
        ),
      ],
    );
  }
}
