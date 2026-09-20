# HackerDummy — operação e manutenção

[Voltar à apresentação](../README.md)

## Mapa de leitura

A documentação principal descreve o fluxo de entrada. Para alterar o projeto, comece pelos contratos abaixo e acompanhe os dados até a persistência ou os artefatos de saída:

- [`labs`](../labs): Alvos sintéticos e gabaritos dos laboratórios.
- [`harness/score_lab.py`](../harness/score_lab.py): Comparação entre achados e gabarito.
- [`run_labs.py`](../run_labs.py): Gerenciamento dos processos de laboratório.
- [`ctf_platform.py`](../ctf_platform.py): Interface local de apoio ao laboratório.
- [`TAXONOMY.md`](../TAXONOMY.md): Vocabulário de classificação.
- [`examples`](../examples): Exemplos de dados do harness.

## Preparar uma instalação ou revisão

1. Registre a revisão Git e leia os manifests desta mesma versão.
2. Prepare um ambiente isolado com dados sintéticos. Identifique dependências externas e quem administra cada uma.
3. Preencha configurações e segredos localmente. Revise os valores padrão e não reutilize credenciais de demonstração.
4. Faça um backup restaurável de qualquer dado existente antes de migrações ou substituição de serviços.
5. Valide o fluxo principal e registre limitações observadas; um processo iniciado não comprova que todo o produto funciona.

## Verificação específica

O harness calcula métricas a partir dos arquivos fornecidos; não é prova de que cada vulnerabilidade foi reproduzida. Confira a taxonomia, o formato dos achados e a independência do gabarito antes de comparar resultados.

## Dados e recuperação

Identifique bancos, volumes e diretórios de evidência nos contratos desta versão. Copiar apenas o código não cria backup dos dados. Uma restauração deve ser ensaiada em ambiente separado, conferindo acesso, vínculos entre entidades e arquivos necessários aos entregáveis. Preserve chaves de cifragem e configuração por canal privado quando forem necessárias à recuperação.

Evite anexar logs brutos a issues: remova tokens, identificadores pessoais e conteúdo de clientes. O mesmo cuidado vale para screenshots, relatórios e exemplos de API.

## Diagnóstico

| Sintoma | Primeira verificação |
| :--- | :--- |
| Processo ou build falha no início | Runtime e dependências contra os manifests da revisão. |
| Interface ou integração indisponível | Endereço configurado, serviço dependente e permissões do ambiente. |
| Dados ausentes ou divergentes | Origem utilizada, revisão do esquema e resultado da importação/ingestão. |
| Exportação ou artefato incompleto | Entrada sintética mínima, arquivos associados e dependências da geração. |

## Limites conhecidos

Os alvos são intencionalmente inseguros. Restrinja a um laboratório local isolado e a dados sintéticos. Não exponha o runner ou aplicações à Internet. O gabarito deve permanecer fora do contexto do agente durante avaliação cega. Métricas deste conjunto não equivalem a garantia de desempenho em produção.

## Critério para atualizar esta documentação

Atualize a apresentação quando mudar nome, entrada, configuração ou responsabilidades. Atualize este guia quando mudar persistência, recuperação ou verificação. Documente comandos e resultados separadamente; só declare um teste aprovado quando houver execução e evidência correspondentes.
