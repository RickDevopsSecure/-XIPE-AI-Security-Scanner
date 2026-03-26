#!/usr/bin/env python3
"""
INBEST AI PENTESTING FRAMEWORK v1.0
=====================================
Herramienta de seguridad ofensiva para evaluación de sistemas de IA.

REQUISITO LEGAL: Este framework SOLO debe ejecutarse contra sistemas
para los cuales se tiene autorización escrita del propietario.
El uso no autorizado es ilegal bajo el Código Penal Federal de México
(Art. 211 bis) y leyes equivalentes internacionales.

Inbest Cybersecurity — https://inbest.cloud
"""
import os
import sys
import argparse
import threading
from pathlib import Path


def parse_args():
    parser = argparse.ArgumentParser(
        description="Inbest AI Pentesting Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python main.py --config config.yaml
  python main.py --config config.yaml --dashboard
  python main.py --config config.yaml --modules api,prompt_injection
  python main.py --config config.yaml --dashboard --dashboard-port 8080
        """
    )
    parser.add_argument(
        "--config", required=True,
        help="Ruta al archivo de configuración YAML del engagement"
    )
    parser.add_argument(
        "--dashboard", action="store_true",
        help="Iniciar el dashboard web en tiempo real"
    )
    parser.add_argument(
        "--dashboard-port", type=int, default=5001,
        help="Puerto del dashboard (default: 5001)"
    )
    parser.add_argument(
        "--modules",
        help="Módulos a ejecutar (separados por coma): api,prompt_injection,rag,agent"
    )
    parser.add_argument(
        "--output-dir", default="output",
        help="Directorio para los archivos de output (default: output)"
    )
    return parser.parse_args()


def main():
    args = parse_args()
    
    # Verificar que el config existe
    config_path = Path(args.config)
    if not config_path.exists():
        print(f"\n❌ Error: No se encontró el archivo de configuración: {config_path}")
        print(f"   Crea uno basándote en config.yaml.example\n")
        sys.exit(1)
    
    # Cargar config para inyectar API keys al env antes de importar módulos
    import yaml
    with open(config_path) as _f:
        _cfg = yaml.safe_load(_f)
    _key = _cfg.get("anthropic_api_key", "")
    if _key and not os.environ.get("ANTHROPIC_API_KEY"):
        os.environ["ANTHROPIC_API_KEY"] = _key

    # Importar aquí para mostrar errores de config antes del import
    from agent.orchestrator import PentestOrchestrator
    
    # Dashboard en thread paralelo
    if args.dashboard:
        from reporting.dashboard import run_dashboard
        dashboard_thread = threading.Thread(
            target=run_dashboard,
            kwargs={
                "port": args.dashboard_port,
                "findings_json_path": f"{args.output_dir}/findings.json",
            },
            daemon=True,
        )
        dashboard_thread.start()
    
    # Ejecutar el engagement
    try:
        orchestrator = PentestOrchestrator(config_path=str(config_path))
        orchestrator.run()
    except ValueError as e:
        print(f"\n❌ Error de configuración: {e}\n")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n⚠ Engagement interrumpido por el usuario.\n")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error inesperado: {e}\n")
        raise


if __name__ == "__main__":
    main()
