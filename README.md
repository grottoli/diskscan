# diskscan

Diagnóstico de espaço em disco para **macOS**. Um único script Python, sem
dependências, **somente leitura** — ele nunca apaga nada.

O `diskscan.py` roda as mesmas varreduras de uma faxina manual (Docker, caches
de dev, modelos de ML, apps, resíduos e conteúdo pessoal), classifica cada
achado por tipo e nível de risco de remoção, e gera um **relatório HTML
autocontido** ordenado pelos maiores tamanhos. Para cada alvo ele sugere o
comando de limpeza — você revisa e decide o que rodar.

## Requisitos

- macOS (alguns caminhos são específicos do sistema)
- Python 3.8+ (só a biblioteca padrão — nada pra instalar)

Para varrer pastas protegidas pelo macOS (ex.: `~/Documents`, `~/Desktop`),
conceda **Full Disk Access** ao seu terminal em
_Ajustes → Privacidade e Segurança → Acesso Total ao Disco_. Sem isso, essas
pastas aparecem como `0` e são ignoradas — o script não falha.

## Uso

```bash
python3 diskscan.py                 # gera ~/disk-report.html e abre no navegador
python3 diskscan.py -o /tmp/r.html  # escolhe o caminho de saída
python3 diskscan.py --no-open       # não abre o navegador automaticamente
python3 diskscan.py --min-mb 100    # ignora alvos menores que 100 MB
```

Ou torne-o executável e rode direto:

```bash
chmod +x diskscan.py
./diskscan.py
```

## Como funciona

- Mede a ocupação real em disco de cada alvo conhecido com `du -sk`.
- Detalha os subitens de 1º nível das "pastas guarda-tudo" (`Application
  Support`, `Caches`, etc.), onde costumam se esconder GB.
- Lista o conteúdo pessoal (fotos, documentos, projetos) apenas como
  referência — nunca como sugestão de remoção.

### Níveis de risco

| Nível              | Significado                                        |
| ------------------ | -------------------------------------------------- |
| **Seguro apagar**  | cache/artefato regenerável; não perde dado real    |
| **Revisar antes**  | pode conter dado seu; olhe antes de apagar         |
| **Conteúdo pessoal** | seus arquivos — decisão de curadoria, não faxina |
| **Resíduo de app** | sobra de app provavelmente já desinstalado         |

## Segurança

O relatório é **somente leitura**: o script mede e reporta, não executa
limpeza. Os comandos exibidos são sugestões — revise cada um antes de rodar,
especialmente os marcados como "revisar antes". Para apps, prefira o
[AppCleaner](https://freemacsoft.net/appcleaner/), que pega resíduos que o
`rm` deixa.

## Licença

MIT — veja [LICENSE](LICENSE).
