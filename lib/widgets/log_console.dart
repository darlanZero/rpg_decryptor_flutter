import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

/// Terminal-style widget para exibir logs em tempo real
class LogConsole extends StatefulWidget {
  final List<String> logs;
  final double height;

  const LogConsole({
    super.key,
    required this.logs,
    this.height = 240,
  });

  @override
  State<LogConsole> createState() => _LogConsoleState();
}

class _LogConsoleState extends State<LogConsole> {
  final ScrollController _scrollController = ScrollController();

  @override
  void didUpdateWidget(LogConsole oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (widget.logs.length != oldWidget.logs.length) {
      WidgetsBinding.instance.addPostFrameCallback((_) => _scrollToBottom());
    }
  }

  void _scrollToBottom() {
    if (_scrollController.hasClients) {
      _scrollController.animateTo(
        _scrollController.position.maxScrollExtent,
        duration: const Duration(milliseconds: 200),
        curve: Curves.easeOut,
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      height: widget.height,
      decoration: BoxDecoration(
        color: const Color(0xFF060612),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: const Color(0xFF2D2D4A), width: 1),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          // Header da console
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
            decoration: const BoxDecoration(
              color: Color(0xFF1A1A2E),
              borderRadius: BorderRadius.only(
                topLeft: Radius.circular(12),
                topRight: Radius.circular(12),
              ),
            ),
            child: Row(
              children: [
                // Dots estilo MacOS
                _dot(const Color(0xFFFF5F57)),
                const SizedBox(width: 6),
                _dot(const Color(0xFFFFBD2E)),
                const SizedBox(width: 6),
                _dot(const Color(0xFF28C840)),
                const SizedBox(width: 12),
                const Text(
                  'Console de Logs',
                  style: TextStyle(
                    color: Colors.white54,
                    fontSize: 12,
                    fontFamily: 'monospace',
                  ),
                ),
                const Spacer(),
                // Botão de copiar logs
                IconButton(
                  icon: const Icon(Icons.copy, size: 16, color: Colors.white38),
                  onPressed: () {
                    Clipboard.setData(
                      ClipboardData(text: widget.logs.join('\n')),
                    );
                    ScaffoldMessenger.of(context).showSnackBar(
                      const SnackBar(
                        content: Text('Logs copiados!'),
                        duration: Duration(seconds: 1),
                      ),
                    );
                  },
                  tooltip: 'Copiar logs',
                  padding: EdgeInsets.zero,
                  constraints: const BoxConstraints(),
                ),
              ],
            ),
          ),
          // Conteúdo
          Expanded(
            child: widget.logs.isEmpty
                ? const Center(
                    child: Text(
                      'Aguardando início...',
                      style: TextStyle(
                        color: Colors.white24,
                        fontFamily: 'monospace',
                        fontSize: 13,
                      ),
                    ),
                  )
                : ListView.builder(
                    controller: _scrollController,
                    padding: const EdgeInsets.all(12),
                    itemCount: widget.logs.length,
                    itemBuilder: (_, i) => _LogLine(log: widget.logs[i]),
                  ),
          ),
        ],
      ),
    );
  }

  Widget _dot(Color color) => Container(
        width: 12,
        height: 12,
        decoration: BoxDecoration(color: color, shape: BoxShape.circle),
      );

  @override
  void dispose() {
    _scrollController.dispose();
    super.dispose();
  }
}

/// Uma linha de log com cor baseada no conteúdo
class _LogLine extends StatelessWidget {
  final String log;
  const _LogLine({required this.log});

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 1.5),
      child: Text(
        log,
        style: TextStyle(
          color: _colorForLog(log),
          fontFamily: 'monospace',
          fontSize: 12.5,
          height: 1.5,
        ),
      ),
    );
  }

  Color _colorForLog(String log) {
    if (log.contains('❌') || log.contains('✗') || log.contains('Erro')) {
      return const Color(0xFFFF6B6B);
    }
    if (log.contains('✅') || log.contains('🎉') || log.contains('CONCLUÍDO')) {
      return const Color(0xFF6BCB77);
    }
    if (log.contains('⚠️') || log.contains('⚠')) {
      return const Color(0xFFFFD93D);
    }
    if (log.contains('🔑') || log.contains('🔒')) {
      return const Color(0xFFAF7EFF);
    }
    if (log.contains('📁') || log.contains('📂') || log.contains('📦')) {
      return const Color(0xFF5DADE2);
    }
    if (log.contains('─')) {
      return const Color(0xFF3D3D5C);
    }
    return const Color(0xFFCCCCCC);
  }
}
