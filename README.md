# hwm-lab

Private trusted Windows/evidence worker repository for the HeroesWM autonomous development infrastructure.

## Trust boundary

- Trusted post-merge validation and evidence jobs belong to the T1 infrastructure boundary.
- Unmerged product candidate code must not receive trusted secrets and must not run on a persistent secret-bearing trusted worker.
- The raw battle corpus is expected to live outside Git and be read-only to ordinary product execution.
- Repository secrets or credentials must not be copied into source control.

I01 creates structure only. It does not implement workers, a job bus, Hyper-V pools, product-candidate execution, corpus storage, or live validation.
