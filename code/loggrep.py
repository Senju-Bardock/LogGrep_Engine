#!/usr/bin/env python3
"""loggrep - Buscador de logs con perfiles JSON (versión Python pura).

Uso rápido:
    python loggrep.py app.log -p errores
    python loggrep.py app.log -e "Timeout" -e "Failed password" -i
    python loggrep.py app.log -p security_audit --export informe.csv
    python loggrep.py --list-profiles

Solo usa la biblioteca estándar. El motor de búsqueda es una función
intercambiable (ver ENGINES): más adelante añadiremos aquí el motor en C.
"""

import argparse
import csv
import json
import os
import re
import sys
import time
from collections import Counter
from pathlib import Path

DEFAULT_QUERIES = Path(__file__).with_name("queries.json")

# --- Colores ANSI -----------------------------------------------------------
RESET = "\033[0m"
HIGHLIGHT = "\033[1;7m"  # negrita + vídeo inverso para la coincidencia
LEVEL_COLORS = {
    "CRITICAL": "\033[1;31m",
    "ERROR": "\033[31m",
    "WARN": "\033[33m",
    "INFO": "\033[32m",
    "DEBUG": "\033[36m",
}


# --- Configuración ----------------------------------------------------------
def load_config(path):
    try:
        with open(path, encoding="utf-8") as f:
            config = json.load(f)
    except FileNotFoundError:
        sys.exit(f"Error: no existe el archivo de perfiles '{path}'.")
    except json.JSONDecodeError as e:
        sys.exit(f"Error: '{path}' no es un JSON válido (línea {e.lineno}, columna {e.colno}): {e.msg}")
    if not isinstance(config.get("profiles", {}), dict):
        sys.exit("Error: 'profiles' debe ser un objeto en queries.json.")
    return config


def build_level_regexes(config):
    """Un regex (sobre bytes) por nivel, en el orden en que aparecen en el JSON."""
    levels = config.get("levels", {})
    result = []
    for name, words in levels.items():
        expr = r"\b(?:" + "|".join(re.escape(w) for w in words) + r")\b"
        result.append((name, re.compile(expr.encode("utf-8"))))
    return result


def classify(line, level_regexes):
    for name, rx in level_regexes:
        if rx.search(line):
            return name
    return None


# --- Matcher ----------------------------------------------------------------
class Matcher:
    """Combina patrones literales y regex en un único regex compilado."""

    def __init__(self, literals, regexes, excludes, ignore_case):
        flags = re.IGNORECASE if ignore_case else 0
        parts = [re.escape(p) for p in literals] + [f"(?:{r})" for r in regexes]
        expr = "|".join(parts)
        try:
            self.include_str = re.compile(expr, flags)
            self.include_bytes = re.compile(expr.encode("utf-8"), flags)
        except re.error as e:
            sys.exit(f"Error en la expresión regular: {e}")
        if excludes:
            exc = "|".join(re.escape(x) for x in excludes)
            self.exclude_bytes = re.compile(exc.encode("utf-8"), flags)
        else:
            self.exclude_bytes = None


# --- Motores de búsqueda ----------------------------------------------------
class Stats:
    def __init__(self):
        self.lines = 0
        self.bytes = 0
        self.matches = 0
        self.levels = Counter()


def search_python(path, matcher, stats):
    """Genera (numero_de_linea, linea_en_bytes) por cada coincidencia.

    Lee en binario y solo decodifica las líneas que coinciden, así que es más
    rápido que trabajar con texto y no falla con codificaciones raras.
    """
    include = matcher.include_bytes.search
    exclude = matcher.exclude_bytes.search if matcher.exclude_bytes else None
    n = 0
    with open(path, "rb") as f:
        try:
            for n, line in enumerate(f, 1):
                if include(line) and not (exclude and exclude(line)):
                    yield n, line.rstrip(b"\r\n")
        finally:
            stats.lines = n
            stats.bytes = f.tell()  # bytes realmente leídos (útil con --max)


# Para añadir el motor en C más adelante: una función con la misma firma que
# search_python que lance el binario con subprocess y vaya produciendo
# (numero, linea_en_bytes) leyendo su stdout.
ENGINES = {"python": search_python}


# --- Salida -----------------------------------------------------------------
def highlight(text, rx, base):
    out, last = [], 0
    for m in rx.finditer(text):
        if m.end() == m.start():
            continue
        out.append(text[last:m.start()])
        out.append(f"{HIGHLIGHT}{m.group()}{RESET}{base}")
        last = m.end()
    out.append(text[last:])
    return "".join(out)


def format_line(n, text, level, rx, use_color):
    if not use_color:
        tag = f"[{level}] " if level else ""
        return f"{n:>9} | {tag}{text}"
    base = LEVEL_COLORS.get(level, "")
    tag = f"[{level}] " if level else ""
    return f"\033[2m{n:>9} |{RESET} {base}{tag}{highlight(text, rx, base)}{RESET}"


class Exporter:
    """Escribe las coincidencias en streaming a .txt, .csv o .json."""

    def __init__(self, path):
        self.kind = Path(path).suffix.lower().lstrip(".")
        if self.kind not in ("txt", "csv", "json"):
            sys.exit("Error: --export debe terminar en .txt, .csv o .json")
        self.f = open(path, "w", encoding="utf-8", newline="")
        self.first = True
        if self.kind == "csv":
            self.writer = csv.writer(self.f)
            self.writer.writerow(["linea", "nivel", "texto"])
        elif self.kind == "json":
            self.f.write("[\n")

    def write(self, n, level, text):
        if self.kind == "txt":
            self.f.write(f"{n}:{level or '-'}|{text}\n")
        elif self.kind == "csv":
            self.writer.writerow([n, level or "", text])
        else:
            if not self.first:
                self.f.write(",\n")
            self.f.write("  " + json.dumps({"linea": n, "nivel": level, "texto": text}, ensure_ascii=False))
            self.first = False

    def close(self):
        if self.kind == "json":
            self.f.write("\n]\n")
        self.f.close()


def print_stats(stats, elapsed):
    mb = stats.bytes / 1_000_000
    rate_mb = mb / elapsed if elapsed > 0 else 0
    rate_lines = stats.lines / elapsed if elapsed > 0 else 0
    print("\n--- Resumen ---", file=sys.stderr)
    print(f"Líneas escaneadas : {stats.lines:,}", file=sys.stderr)
    print(f"Coincidencias     : {stats.matches:,}", file=sys.stderr)
    if stats.levels:
        detail = ", ".join(f"{k}={v:,}" for k, v in stats.levels.most_common())
        print(f"Por nivel         : {detail}", file=sys.stderr)
    print(f"Tiempo            : {elapsed:.2f} s", file=sys.stderr)
    print(f"Velocidad         : {rate_mb:,.1f} MB/s ({rate_lines:,.0f} líneas/s)", file=sys.stderr)


# --- CLI --------------------------------------------------------------------
def parse_args():
    p = argparse.ArgumentParser(description="Buscador de logs con perfiles JSON.")
    p.add_argument("file", nargs="?", help="archivo de log a analizar")
    p.add_argument("-p", "--profile", help="nombre del perfil en queries.json")
    p.add_argument("-q", "--queries", default=str(DEFAULT_QUERIES), help="ruta del JSON de perfiles")
    p.add_argument("-e", "--pattern", action="append", default=[], help="texto literal a buscar (repetible)")
    p.add_argument("-r", "--regex", action="append", default=[], help="expresión regular (repetible)")
    p.add_argument("-x", "--exclude", action="append", default=[], help="excluir líneas con este texto (repetible)")
    p.add_argument("-i", "--ignore-case", action="store_true", help="ignorar mayúsculas/minúsculas")
    p.add_argument("-m", "--max", type=int, default=0, help="parar tras N coincidencias")
    p.add_argument("--count", action="store_true", help="no imprimir líneas, solo el resumen")
    p.add_argument("--export", metavar="ARCHIVO", help="exportar coincidencias (.txt, .csv o .json)")
    p.add_argument("--no-color", action="store_true", help="desactivar colores")
    p.add_argument("--engine", choices=sorted(ENGINES), default="python", help="motor de búsqueda")
    p.add_argument("--list-profiles", action="store_true", help="listar perfiles disponibles y salir")
    return p.parse_args()


def setup_console():
    # Que cmd de Windows interprete los códigos ANSI y muestre UTF-8.
    os.system("")
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except AttributeError:
            pass


def main():
    setup_console()
    args = parse_args()
    config = load_config(args.queries)
    profiles = config.get("profiles", {})

    if args.list_profiles:
        for name, prof in profiles.items():
            print(f"{name:<16} {prof.get('description', '')}")
        return

    if not args.file:
        sys.exit("Error: indica el archivo de log. Ejemplo: python loggrep.py app.log -p errores")
    if not os.path.isfile(args.file):
        sys.exit(f"Error: no existe el archivo '{args.file}'.")

    literals, regexes, excludes = list(args.pattern), list(args.regex), list(args.exclude)
    severity, ignore_case = None, args.ignore_case
    if args.profile:
        prof = profiles.get(args.profile)
        if prof is None:
            sys.exit(f"Error: el perfil '{args.profile}' no existe. Disponibles: {', '.join(profiles) or '(ninguno)'}")
        literals += prof.get("patterns", [])
        regexes += prof.get("regex", []) if isinstance(prof.get("regex", []), list) else [prof["regex"]]
        excludes += prof.get("exclude", [])
        severity = prof.get("severity")
        ignore_case = ignore_case or prof.get("ignore_case", False)

    if not literals and not regexes:
        sys.exit("Error: indica un perfil (-p) o al menos un patrón (-e) o regex (-r).")

    matcher = Matcher(literals, regexes, excludes, ignore_case)
    level_regexes = build_level_regexes(config)
    use_color = not args.no_color and sys.stdout.isatty()
    exporter = Exporter(args.export) if args.export else None
    stats = Stats()
    engine = ENGINES[args.engine]

    start = time.perf_counter()
    results = engine(args.file, matcher, stats)
    try:
        for n, raw in results:
            stats.matches += 1
            level = classify(raw, level_regexes) or severity
            stats.levels[level or "SIN_NIVEL"] += 1
            text = raw.decode("utf-8", errors="replace")
            if exporter:
                exporter.write(n, level, text)
            if not args.count:
                print(format_line(n, text, level, matcher.include_str, use_color))
            if args.max and stats.matches >= args.max:
                results.close()
                break
    except BrokenPipeError:
        # Por ejemplo: python loggrep.py app.log -p errores | more
        sys.stderr.close()
        return
    finally:
        if exporter:
            exporter.close()
    print_stats(stats, time.perf_counter() - start)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
