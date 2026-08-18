#!/usr/bin/env python3
"""
diskscan.py — Diagnóstico de espaço em disco para macOS.

Roda as mesmas varreduras de uma faxina manual (Docker, caches de dev,
modelos de ML, apps, resíduos de apps desinstalados, conteúdo pessoal),
classifica cada achado por tipo e nível de risco de remoção, e gera um
relatório HTML autocontido ordenado pelos maiores tamanhos.

Uso:
    python3 diskscan.py                 # gera ~/disk-report.html e abre no navegador
    python3 diskscan.py -o /tmp/r.html  # escolhe o caminho de saída
    python3 diskscan.py --no-open       # não abre o navegador automaticamente
    python3 diskscan.py --min-mb 100    # ignora itens menores que 100 MB nas listas longas

Só usa a stdlib. Nada pra instalar.
Somente leitura: NÃO apaga nada. Ele sugere comandos; você decide e executa.
"""

import argparse
import datetime
import html
import os
import shutil
import subprocess
import sys
import webbrowser
from pathlib import Path

HOME = Path.home()

# ---------------------------------------------------------------------------
# Definição das áreas varridas.
#
# Cada "probe" é um alvo conhecido. risk:
#   safe    -> cache/artefato regenerável; apagar não perde dado real
#   review  -> pode conter dado seu; olhar antes
#   content -> conteúdo pessoal (fotos, projetos); nunca é "lixo" por definição
#   residue -> sobra de app provavelmente já desinstalado
#
# 'hint' explica o que é. 'cmd' é o comando sugerido de limpeza (informativo).
# ---------------------------------------------------------------------------

PROBES = [
    # ---- Docker -----------------------------------------------------------
    {
        "label": "Docker — imagem de disco da VM (Docker.raw)",
        "path": HOME / "Library/Containers/com.docker.docker/Data/vms/0/data/Docker.raw",
        "category": "Docker",
        "risk": "review",
        "hint": "Disco da VM do Docker. Limpe por 'docker system prune -a' (com o daemon no ar); "
                "o .raw pode não encolher sozinho — reduza em Settings → Resources se preciso.",
        "cmd": "docker system prune -a   # NÃO adicione --volumes sem checar 'docker volume ls'",
    },
    # ---- Caches de dev regeneráveis --------------------------------------
    {
        "label": "npm — cache",
        "path": HOME / ".npm",
        "category": "Cache de dev",
        "risk": "safe",
        "hint": "Cache do npm. Regenera sob demanda.",
        "cmd": "npm cache clean --force",
    },
    {
        "label": "uv — cache",
        "path": HOME / ".cache/uv",
        "category": "Cache de dev",
        "risk": "safe",
        "hint": "Cache de pacotes Python do uv (Astral). Regenera sob demanda.",
        "cmd": "uv cache clean",
    },
    {
        "label": "pip — cache",
        "path": HOME / "Library/Caches/pip",
        "category": "Cache de dev",
        "risk": "safe",
        "hint": "Cache do pip. Regenera sob demanda.",
        "cmd": "pip cache purge",
    },
    {
        "label": "Maven — repositório local (.m2)",
        "path": HOME / ".m2/repository",
        "category": "Cache de dev",
        "risk": "safe",
        "hint": "Artefatos Maven. Rebaixa no próximo build. Preserve ~/.m2/settings.xml.",
        "cmd": "rm -rf ~/.m2/repository",
    },
    {
        "label": "Gradle — caches",
        "path": HOME / ".gradle/caches",
        "category": "Cache de dev",
        "risk": "safe",
        "hint": "Cache do Gradle. Rebaixa no próximo build.",
        "cmd": "rm -rf ~/.gradle/caches",
    },
    {
        "label": "Yarn — cache",
        "path": HOME / "Library/Caches/Yarn",
        "category": "Cache de dev",
        "risk": "safe",
        "hint": "Cache do Yarn. Regenera sob demanda.",
        "cmd": "yarn cache clean",
    },
    {
        "label": "node-gyp — cache",
        "path": HOME / "Library/Caches/node-gyp",
        "category": "Cache de dev",
        "risk": "safe",
        "hint": "Headers do Node p/ builds nativos. Rebaixa sob demanda.",
        "cmd": "rm -rf ~/Library/Caches/node-gyp",
    },
    {
        "label": "Homebrew — cache de downloads",
        "path": HOME / "Library/Caches/Homebrew",
        "category": "Cache de dev",
        "risk": "safe",
        "hint": "Tarballs baixados pelo brew. Seguro limpar.",
        "cmd": "brew cleanup -s",
    },
    {
        "label": "Playwright — browsers",
        "path": HOME / "Library/Caches/ms-playwright",
        "category": "Cache de dev",
        "risk": "review",
        "hint": "Browsers do Playwright p/ testes E2E. Se usa em projeto, mantenha.",
        "cmd": "npx playwright uninstall",
    },
    {
        "label": "Electron — cache",
        "path": HOME / "Library/Caches/electron",
        "category": "Cache de dev",
        "risk": "safe",
        "hint": "Binários do Electron em cache. Rebaixa sob demanda.",
        "cmd": "rm -rf ~/Library/Caches/electron",
    },
    # ---- Modelos de ML ----------------------------------------------------
    {
        "label": "Hugging Face — modelos/datasets",
        "path": HOME / ".cache/huggingface",
        "category": "Modelo de ML",
        "risk": "review",
        "hint": "Modelos/datasets baixados. Podem ser grandes e você talvez queira manter.",
        "cmd": "rm -rf ~/.cache/huggingface   # só se não for reusar os modelos",
    },
    {
        "label": "Unsloth — fine-tuning",
        "path": HOME / ".unsloth",
        "category": "Modelo de ML",
        "risk": "review",
        "hint": "Artefatos de fine-tuning de LLM. Descartável se não há treino em andamento.",
        "cmd": "rm -rf ~/.unsloth   # só se foi experimento pontual",
    },
    {
        "label": "Ollama — modelos",
        "path": HOME / ".ollama/models",
        "category": "Modelo de ML",
        "risk": "review",
        "hint": "Modelos LLM locais do Ollama. Grandes; apague só os que não usa.",
        "cmd": "ollama list   # e 'ollama rm <modelo>' nos que não usa",
    },
    # ---- Claude Desktop ---------------------------------------------------
    {
        "label": "Claude Desktop — VM sandbox (vm_bundles)",
        "path": HOME / "Library/Application Support/Claude/vm_bundles",
        "category": "Sandbox / VM",
        "risk": "review",
        "hint": "VM do ambiente de execução do Claude Desktop. Recriável. Feche o app antes de apagar.",
        "cmd": 'osascript -e \'quit app "Claude"\'; rm -rf ~/Library/Application\\ Support/Claude/vm_bundles/*',
    },
    # ---- Navegadores ------------------------------------------------------
    {
        "label": "Chrome — modelo de IA on-device",
        "path": HOME / "Library/Application Support/Google/Chrome/OptGuideOnDeviceModel",
        "category": "Navegador",
        "risk": "safe",
        "hint": "Modelo Gemini Nano on-device. Desative em chrome://settings/ai p/ remover limpo.",
        "cmd": "# chrome://settings/ai  → desativar IA on-device",
    },
    {
        "label": "Spotify — cache",
        "path": HOME / "Library/Caches/com.spotify.client",
        "category": "App / mídia",
        "risk": "safe",
        "hint": "Áudio pré-carregado. Regenera. Settings → Storage → Clear cache.",
        "cmd": "rm -rf ~/Library/Caches/com.spotify.client/*",
    },
    # ---- Lixeira e snapshots ---------------------------------------------
    {
        "label": "Lixeira",
        "path": HOME / ".Trash",
        "category": "Sistema",
        "risk": "safe",
        "hint": "Itens na lixeira. Esvazie se já revisou.",
        "cmd": "# Finder → Esvaziar Lixo, ou: rm -rf ~/.Trash/*",
    },
]

# Diretórios cujo conteúdo (subpastas de 1º nível) vale detalhar,
# porque frequentemente escondem GB em subitens (ex.: ~/.gemini com antigravity).
DEEP_DIRS = [
    (HOME / "Library/Application Support", "Application Support (dados de apps)"),
    (HOME / "Library/Caches", "Caches gerais"),
    (HOME / ".gemini", "~/.gemini"),
]

# Áreas de conteúdo pessoal — reportadas, nunca sugeridas p/ remoção.
CONTENT_DIRS = [
    (HOME / "Pictures", "Fotos e imagens"),
    (HOME / "Documents", "Documentos"),
    (HOME / "Downloads", "Downloads"),
    (HOME / "Movies", "Vídeos"),
    (HOME / "Music", "Música"),
    (HOME / "Desktop", "Área de trabalho"),
    (HOME / "work", "Projetos (~/work)"),
]

RISK_META = {
    "safe":    ("Seguro apagar", "regenera ou é descartável"),
    "review":  ("Revisar antes", "pode conter dado seu"),
    "content": ("Conteúdo pessoal", "não é lixo — decisão sua"),
    "residue": ("Resíduo de app", "sobra de app desinstalado"),
}


# ---------------------------------------------------------------------------
# Utilidades de medição
# ---------------------------------------------------------------------------

def du_bytes(path: Path) -> int:
    """Ocupação real em disco (bytes), via `du -sk`. Retorna 0 se não existe/sem permissão."""
    if not path.exists():
        return 0
    try:
        out = subprocess.run(
            ["du", "-sk", str(path)],
            capture_output=True, text=True, timeout=120,
        )
        if out.returncode != 0 and not out.stdout.strip():
            return 0
        kb = int(out.stdout.split("\t")[0].strip())
        return kb * 1024
    except (subprocess.TimeoutExpired, ValueError, IndexError):
        return 0


def children_sizes(path: Path, top: int = 12) -> list:
    """Tamanho de cada subitem de 1º nível, ordenado desc. Lista de (nome, bytes)."""
    if not path.is_dir():
        return []
    rows = []
    try:
        for child in path.iterdir():
            b = du_bytes(child)
            if b > 0:
                rows.append((child.name, b))
    except PermissionError:
        return []
    rows.sort(key=lambda r: r[1], reverse=True)
    return rows[:top]


def human(nbytes: int) -> str:
    if nbytes <= 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    v = float(nbytes)
    for u in units:
        if v < 1024 or u == units[-1]:
            return f"{v:.1f} {u}" if u != "B" else f"{int(v)} {u}"
        v /= 1024


def disk_free() -> dict:
    """Espaço total/usado/livre do volume raiz."""
    total, used, free = shutil.disk_usage("/")
    return {"total": total, "used": used, "free": free,
            "pct_used": round(used / total * 100)}


# ---------------------------------------------------------------------------
# Coleta
# ---------------------------------------------------------------------------

def collect():
    probes = []
    for p in PROBES:
        size = du_bytes(p["path"])
        if size <= 0:
            continue
        item = dict(p)
        item["size"] = size
        item["path_str"] = str(p["path"]).replace(str(HOME), "~")
        probes.append(item)
    probes.sort(key=lambda x: x["size"], reverse=True)

    deep = []
    for path, title in DEEP_DIRS:
        rows = children_sizes(path, top=12)
        if rows:
            deep.append({
                "title": title,
                "path_str": str(path).replace(str(HOME), "~"),
                "total": du_bytes(path),
                "rows": [(n, b, human(b)) for n, b in rows],
            })

    content = []
    for path, title in CONTENT_DIRS:
        size = du_bytes(path)
        if size > 0:
            content.append({
                "title": title,
                "path_str": str(path).replace(str(HOME), "~"),
                "size": size,
            })
    content.sort(key=lambda x: x["size"], reverse=True)

    return probes, deep, content


# ---------------------------------------------------------------------------
# Render HTML
# ---------------------------------------------------------------------------

def render(probes, deep, content, disk) -> str:
    now = datetime.datetime.now().strftime("%d/%m/%Y %H:%M")
    hostname = os.uname().nodename

    reclaimable_safe = sum(p["size"] for p in probes if p["risk"] == "safe")
    reclaimable_review = sum(p["size"] for p in probes if p["risk"] == "review")

    max_probe = max((p["size"] for p in probes), default=1)

    def esc(s):
        return html.escape(str(s))

    # ---- linhas de probes ----
    probe_rows = []
    for p in probes:
        label_txt, _ = RISK_META[p["risk"]]
        bar_pct = max(2, round(p["size"] / max_probe * 100))
        probe_rows.append(f"""
        <tr class="risk-{p['risk']}">
          <td class="cat">{esc(p['category'])}</td>
          <td class="name">
            <div class="nm">{esc(p['label'])}</div>
            <div class="pth">{esc(p['path_str'])}</div>
          </td>
          <td class="sz">
            <div class="szval">{esc(human(p['size']))}</div>
            <div class="bar"><span style="width:{bar_pct}%"></span></div>
          </td>
          <td><span class="pill pill-{p['risk']}">{esc(label_txt)}</span></td>
          <td class="hint">{esc(p['hint'])}<div class="cmd">{esc(p['cmd'])}</div></td>
        </tr>""")

    # ---- blocos deep ----
    deep_blocks = []
    for d in deep:
        rows = "".join(
            f"<tr><td class='dn'>{esc(n)}</td><td class='ds'>{esc(hh)}</td></tr>"
            for n, b, hh in d["rows"]
        )
        deep_blocks.append(f"""
        <div class="deep-card">
          <div class="deep-head">
            <h3>{esc(d['title'])}</h3>
            <div class="deep-meta">{esc(d['path_str'])} · total {esc(human(d['total']))}</div>
          </div>
          <table class="deep-tbl"><tbody>{rows}</tbody></table>
        </div>""")

    # ---- conteúdo pessoal ----
    content_rows = "".join(
        f"""<tr>
          <td class="name"><div class="nm">{esc(c['title'])}</div>
              <div class="pth">{esc(c['path_str'])}</div></td>
          <td class="sz"><div class="szval">{esc(human(c['size']))}</div></td>
        </tr>""" for c in content
    )

    return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Diagnóstico de disco · {esc(hostname)}</title>
<style>
  :root {{
    --ink: #10221f;
    --paper: #f3f0e7;
    --card: #ffffff;
    --line: #d9d3c4;
    --muted: #6c6a5f;
    --deep: #0f4c43;
    --safe: #1f7a4d;
    --safe-bg: #e2f2e8;
    --review: #a5641a;
    --review-bg: #f7ecd9;
    --content: #3a4a8c;
    --content-bg: #e6e9f6;
    --accent: #d8552f;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; background: var(--paper); color: var(--ink);
    font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
    padding: 0 20px 80px;
  }}
  .wrap {{ max-width: 1040px; margin: 0 auto; }}

  header.top {{ padding: 44px 0 20px; border-bottom: 2px solid var(--ink); }}
  .kicker {{ font-size: 12px; letter-spacing: .18em; text-transform: uppercase;
             color: var(--deep); font-weight: 700; }}
  h1 {{ font-size: 34px; margin: 6px 0 2px; letter-spacing: -.01em; }}
  .sub {{ color: var(--muted); font-size: 14px; }}

  .gauge {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px,1fr));
            gap: 14px; margin: 26px 0 8px; }}
  .stat {{ background: var(--card); border: 1px solid var(--line); border-radius: 12px;
           padding: 16px 18px; }}
  .stat .lab {{ font-size: 11px; letter-spacing: .1em; text-transform: uppercase;
                color: var(--muted); }}
  .stat .val {{ font-size: 26px; font-weight: 700; margin-top: 4px; }}
  .stat .val small {{ font-size: 14px; font-weight: 500; color: var(--muted); }}

  .diskbar {{ height: 20px; border-radius: 999px; overflow: hidden; display: flex;
              border: 1px solid var(--line); margin: 20px 0 4px; background: #e8e4d8; }}
  .diskbar .u {{ background: linear-gradient(90deg,var(--accent),#e08a4a); }}
  .diskbar .f {{ background: #cfe6d8; }}
  .diskbar-key {{ font-size: 12px; color: var(--muted); display: flex; gap: 18px; }}
  .diskbar-key b {{ color: var(--ink); }}

  h2.sec {{ font-size: 13px; letter-spacing: .16em; text-transform: uppercase;
            color: var(--deep); margin: 44px 0 6px; border-bottom: 1px solid var(--line);
            padding-bottom: 6px; }}
  .sec-note {{ color: var(--muted); font-size: 13px; margin: 0 0 14px; }}

  table.main {{ width: 100%; border-collapse: collapse; background: var(--card);
                border: 1px solid var(--line); border-radius: 12px; overflow: hidden; }}
  table.main th {{ text-align: left; font-size: 11px; letter-spacing: .08em;
                   text-transform: uppercase; color: var(--muted); padding: 12px 14px;
                   border-bottom: 1px solid var(--line); background: #faf8f1; }}
  table.main td {{ padding: 13px 14px; border-bottom: 1px solid #ece8dc;
                   vertical-align: top; }}
  table.main tr:last-child td {{ border-bottom: none; }}
  .cat {{ font-size: 12px; color: var(--deep); font-weight: 600; white-space: nowrap; }}
  .nm {{ font-weight: 600; }}
  .pth {{ font-family: ui-monospace, "SF Mono", Menlo, monospace; font-size: 12px;
          color: var(--muted); margin-top: 2px; word-break: break-all; }}
  .sz {{ white-space: nowrap; }}
  .szval {{ font-weight: 700; font-size: 15px; }}
  .bar {{ height: 5px; background: #ece8dc; border-radius: 3px; margin-top: 5px;
          width: 120px; overflow: hidden; }}
  .bar span {{ display: block; height: 100%; background: var(--accent); }}
  .hint {{ font-size: 13px; color: #4a4a42; max-width: 340px; }}
  .cmd {{ font-family: ui-monospace, "SF Mono", Menlo, monospace; font-size: 11.5px;
          background: #10221f; color: #d9f2e4; padding: 6px 9px; border-radius: 6px;
          margin-top: 7px; white-space: pre-wrap; word-break: break-all;
          -webkit-user-select: all; user-select: all; }}

  .pill {{ font-size: 11px; font-weight: 700; padding: 3px 9px; border-radius: 999px;
           white-space: nowrap; }}
  .pill-safe {{ background: var(--safe-bg); color: var(--safe); }}
  .pill-review {{ background: var(--review-bg); color: var(--review); }}
  .pill-content {{ background: var(--content-bg); color: var(--content); }}
  .pill-residue {{ background: var(--review-bg); color: var(--review); }}

  .deep-grid {{ display: grid; grid-template-columns: repeat(auto-fit,minmax(300px,1fr));
                gap: 16px; }}
  .deep-card {{ background: var(--card); border: 1px solid var(--line);
                border-radius: 12px; padding: 16px 18px; }}
  .deep-head h3 {{ margin: 0; font-size: 15px; }}
  .deep-meta {{ font-family: ui-monospace, Menlo, monospace; font-size: 11px;
                color: var(--muted); margin: 3px 0 10px; word-break: break-all; }}
  .deep-tbl {{ width: 100%; border-collapse: collapse; }}
  .deep-tbl td {{ padding: 5px 0; border-bottom: 1px dotted #e2ddcf; font-size: 13px; }}
  .deep-tbl tr:last-child td {{ border-bottom: none; }}
  .dn {{ font-family: ui-monospace, Menlo, monospace; font-size: 12px;
         word-break: break-all; padding-right: 10px; }}
  .ds {{ text-align: right; font-weight: 700; white-space: nowrap; }}

  footer {{ margin-top: 46px; padding-top: 18px; border-top: 1px solid var(--line);
            color: var(--muted); font-size: 12px; }}
  footer code {{ background: #e8e4d8; padding: 1px 5px; border-radius: 4px; }}
  .warn {{ background: var(--review-bg); border: 1px solid #e6cfa6; border-radius: 10px;
           padding: 12px 15px; font-size: 13px; color: #6b4d18; margin: 16px 0 0; }}
</style>
</head>
<body>
<div class="wrap">

  <header class="top">
    <div class="kicker">Diagnóstico de disco</div>
    <h1>Onde o espaço foi parar</h1>
    <div class="sub">{esc(hostname)} · gerado em {esc(now)} · somente leitura, nada foi apagado</div>
  </header>

  <div class="diskbar">
    <div class="u" style="width:{disk['pct_used']}%"></div>
    <div class="f" style="width:{100 - disk['pct_used']}%"></div>
  </div>
  <div class="diskbar-key">
    <span>Volume raiz: <b>{esc(human(disk['total']))}</b></span>
    <span>Usado: <b>{esc(human(disk['used']))}</b> ({disk['pct_used']}%)</span>
    <span>Livre: <b>{esc(human(disk['free']))}</b></span>
  </div>

  <div class="gauge">
    <div class="stat">
      <div class="lab">Recuperável — seguro</div>
      <div class="val">{esc(human(reclaimable_safe))}</div>
    </div>
    <div class="stat">
      <div class="lab">Recuperável — a revisar</div>
      <div class="val">{esc(human(reclaimable_review))}</div>
    </div>
    <div class="stat">
      <div class="lab">Alvos encontrados</div>
      <div class="val">{len(probes)}</div>
    </div>
  </div>

  <h2 class="sec">Alvos de limpeza · ordenados por tamanho</h2>
  <p class="sec-note">Clique num comando p/ selecioná-lo. Confira sempre antes de rodar —
     "a revisar" pode conter dado seu.</p>
  <table class="main">
    <thead><tr>
      <th>Tipo</th><th>Item</th><th>Tamanho</th><th>Risco</th><th>O que é · como limpar</th>
    </tr></thead>
    <tbody>{''.join(probe_rows)}</tbody>
  </table>

  <h2 class="sec">Raio-X de pastas guarda-tudo</h2>
  <p class="sec-note">Onde a categoria "Documents"/"Applications" do macOS costuma esconder GB.
     Subitens de 1º nível, maiores primeiro.</p>
  <div class="deep-grid">{''.join(deep_blocks) or '<p class="sec-note">Nada relevante encontrado.</p>'}</div>

  <h2 class="sec">Conteúdo pessoal · não é lixo</h2>
  <p class="sec-note">Listado só p/ referência. São seus arquivos — decisão de curadoria, não faxina.</p>
  <table class="main"><tbody>{content_rows or '<tr><td class=hint>Nada encontrado.</td></tr>'}</tbody></table>

  <div class="warn">
    Este relatório é <b>somente leitura</b>. Ele não apagou nada. Os comandos são sugestões —
    revise cada um, especialmente os marcados como "a revisar", antes de executar.
    Para apps, prefira o AppCleaner (pega resíduos que o <code>rm</code> deixa).
  </div>

  <footer>
    Gerado por <code>diskscan.py</code> · rode de novo quando a categoria "Documents" inflar.
    Método: <code>du -sk</code> por alvo conhecido + varredura de 1º nível das pastas guarda-tudo.
    Pastas protegidas pelo macOS (sem Full Disk Access) aparecem como 0 e são ignoradas.
  </footer>

</div>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Diagnóstico de disco (macOS) → relatório HTML.")
    ap.add_argument("-o", "--output", default=str(HOME / "disk-report.html"),
                    help="caminho do HTML de saída (padrão: ~/disk-report.html)")
    ap.add_argument("--no-open", action="store_true", help="não abrir o navegador")
    ap.add_argument("--min-mb", type=int, default=0,
                    help="ignora alvos menores que N MB (padrão: 0 = mostra tudo)")
    args = ap.parse_args()

    if sys.platform != "darwin":
        print("Aviso: pensado p/ macOS. Alguns caminhos podem não existir em outros sistemas.",
              file=sys.stderr)

    print("Varrendo… (pode levar alguns segundos)", file=sys.stderr)
    probes, deep, content = collect()

    if args.min_mb:
        threshold = args.min_mb * 1024 * 1024
        probes = [p for p in probes if p["size"] >= threshold]

    disk = disk_free()
    out_html = render(probes, deep, content, disk)

    out_path = Path(args.output).expanduser()
    out_path.write_text(out_html, encoding="utf-8")
    print(f"Relatório salvo em: {out_path}", file=sys.stderr)

    if not args.no_open:
        webbrowser.open(f"file://{out_path}")


if __name__ == "__main__":
    main()
