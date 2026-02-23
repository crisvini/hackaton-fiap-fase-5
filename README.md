# Hackathon FIAP Fase 5 - MVP de Modelagem de Ameacas com IA (Python + OpenAI)

## Visao do projeto (para avaliacao)

Este repositorio implementa um MVP para o desafio de "Modelagem de ameacas utilizando IA", com foco em validar a viabilidade da feature proposta no PDF do hackathon.

O sistema recebe um diagrama de arquitetura em imagem, identifica componentes e fluxos, e gera um relatorio de ameacas baseado na metodologia STRIDE, com vulnerabilidades e contramedidas sugeridas.

## Objetivo atendido (resumo)

Com base no enunciado do PDF, este projeto atende os pontos principais do MVP:

- Interpretacao automatica de diagrama de arquitetura em imagem (OpenAI Vision)
- Identificacao de componentes e fluxos
- Geracao de relatorio STRIDE
- Associacao de vulnerabilidades e contramedidas por tipo de componente
- Fluxo de auto-anotacao de dataset (para apoiar a etapa supervisionada em uma fase seguinte)

Observacao:
- O treino de modelo supervisionado nao foi implementado neste MVP (fase 2 sugerida), mas o projeto ja possui um script para acelerar anotacao de dataset.

## Como a solucao funciona

Pipeline principal:

1. Entrada: imagem de arquitetura (`.png`, `.jpg`, `.jpeg`, `.webp`)
2. OpenAI Vision extrai uma arquitetura estruturada:
   - componentes
   - fluxos de dados
   - trust boundaries
   - ambiguidades/hipoteses
3. Geracao de ameacas STRIDE:
   - preferencialmente com LLM
   - com fallback para um catalogo local (`kb/stride_component_catalog.yaml`) quando necessario
4. Saida:
   - `architecture.json`
   - `threat_report.json`
   - `threat_report.md`

## Estrutura de pastas (resumo)

- `src/stride_mvp`: codigo principal (CLI, API, pipeline, integracao OpenAI)
- `kb`: catalogo local de ameacas/mitigacoes STRIDE por componente
- `scripts`: scripts auxiliares (ex.: auto-anotacao de dataset)
- `diagramas_reais`: pasta para colocar os diagramas de teste reais
- `outputs`: resultados gerados nas execucoes

## Requisitos

- Python 3.10+
- Conta OpenAI com chave de API valida

## Configuracao obrigatoria (.env)

Quem for executar o projeto precisa criar um arquivo `.env` na raiz do repositorio, usando o arquivo `.env.example` como modelo, e informar uma chave valida da OpenAI.

Passos:

```powershell
Copy-Item .env.example .env
```

Depois, editar o arquivo `.env` e preencher:

```env
OPENAI_API_KEY=sk-...   # chave valida da OpenAI (obrigatorio)
OPENAI_MODEL_VISION=gpt-4.1-mini
OPENAI_MODEL_THREATS=gpt-4.1-mini
```

Sem uma chave valida da OpenAI, a etapa de leitura do diagrama por imagem nao funciona.

## Como rodar o projeto (Windows / PowerShell)

### 1) Criar e ativar ambiente virtual

```powershell
python -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

### 2) Instalar dependencias

```powershell
pip install -e .
```

### 3) Colocar os diagramas na pasta correta

Coloque as imagens em:

- `diagramas_reais`

Exemplo:

- `diagramas_reais\1.png`
- `diagramas_reais\2.png`

### 4) Executar a analise (imagem -> relatorio STRIDE)

Exemplo de execucao:

```powershell
stride-mvp analyze --image .\diagramas_reais\1.png --output-dir .\outputs\real_1
```

Outro exemplo:

```powershell
stride-mvp analyze --image .\diagramas_reais\2.png --output-dir .\outputs\real_2
```

### 5) Ver os resultados

Cada execucao gera:

- `architecture.json` (arquitetura extraida)
- `threat_report.json` (relatorio estruturado)
- `threat_report.md` (relatorio legivel para apresentacao)

Exemplo:

- `outputs\real_1\architecture.json`
- `outputs\real_1\threat_report.json`
- `outputs\real_1\threat_report.md`

## Execucao alternativa (API FastAPI - opcional)

Subir API local:

```powershell
stride-mvp serve --host 127.0.0.1 --port 8000
```

Endpoints:

- `GET /health`
- `POST /analyze` (upload de imagem)

## Script de auto-anotacao de dataset (apoio a fase supervisionada)

Este script usa OpenAI Vision para gerar anotacoes iniciais de componentes e fluxos a partir de imagens de diagramas.

Exemplo:

```powershell
python .\scripts\auto_annotate_dataset.py --input-dir .\diagramas_reais --output-dir .\outputs\dataset_annotations_real
```

Uso esperado:

- acelerar criacao de dataset inicial
- revisar anotacoes manualmente
- usar como base para treino supervisionado em uma fase futura

## Limitacoes do MVP (importante para avaliacao)

- A extracao por IA pode variar entre execucoes e exige revisao humana em diagramas complexos.
- Em alguns casos, a etapa de ameacas pode usar fallback local (catalogo STRIDE) em vez de LLM, para garantir robustez.
- O treino do modelo supervisionado (detector) nao faz parte desta entrega; o projeto entrega a base para isso (anotacao automatica + pipeline).

## Evidencia de viabilidade (o que o professor pode verificar)

Ao executar o comando com uma imagem em `diagramas_reais`, o professor deve conseguir:

- obter um `architecture.json` com componentes e fluxos
- obter um `threat_report.md` com ameacas STRIDE
- verificar contramedidas e monitoracao propostas

Isso demonstra a viabilidade tecnica da feature solicitada no enunciado para uma fase MVP.

